#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;

// Groups allocation and deallocation functions.
enum AllocationFamily : unsigned {
  AF_None,
  AF_Glib,
  AF_GlibStringVector,
  AF_WmemNullScope,
  AF_WmemEpanScope,
  AF_WmemFileScope,
  AF_WmemPacketScope,
  AF_WmemOther
};

bool isWmemAllocationFamily(AllocationFamily family) {
  return family == AF_WmemNullScope || family == AF_WmemEpanScope ||
         family == AF_WmemFileScope || family == AF_WmemPacketScope ||
         family == AF_WmemOther;
}

class AllocState {
  enum Kind : unsigned { Allocated, Freed };
  unsigned K : 1;
  unsigned Family : 31;

  AllocState(Kind InK, AllocationFamily family) : K(InK), Family(family) {
    assert(family != AF_None);
  }

public:
  bool isAllocated() const { return K == Allocated; }
  bool isFreed() const { return K == Freed; }
  bool isFamily(AllocationFamily family) const { return Family == family; }
  AllocationFamily getAllocationFamily() const {
    return (AllocationFamily)Family;
  }

  /// Returns true if this is scoped wmem-allocated memory that is automatically
  /// freed when the scope is left.
  bool isManagedDeallocation() const {
    return isWmemAllocationFamily((AllocationFamily)Family) &&
           Family != AF_WmemNullScope;
  }

  static AllocState getAllocated(AllocationFamily family) {
    return AllocState(Allocated, family);
  }
  static AllocState getFreed(AllocationFamily family) {
    return AllocState(Freed, family);
  }

  bool operator==(const AllocState &X) const {
    return X.K == K && X.Family == Family;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddInteger(Family);
  }
};

class AllocFreeChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols,
                     check::PointerEscape> {
  std::unique_ptr<BugType> AllocDeallocMismatchBugType;
  std::unique_ptr<BugType> DoubleFreeBugType;
  std::unique_ptr<BugType> LeakBugType;

  void reportAllocDeallocMismatch(SymbolRef AddressSym, const CallEvent &Call,
                                  CheckerContext &C,
                                  AllocationFamily family) const;

  void reportDoubleFree(SymbolRef AddressSym, const CallEvent &Call,
                        CheckerContext &C, const char *msg) const;

  void reportLeaks(ArrayRef<SymbolRef> LeakedAddresses, CheckerContext &C,
                   ExplodedNode *ErrNode) const;

public:
  AllocFreeChecker();

  /// Process alloc.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  /// Process free.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;

  /// The bug visitor which allows us to print extra diagnostics along the
  /// BugReport path. For example, showing the allocation site of the leaked
  /// region.
  class MallocBugVisitor final
      : public BugReporterVisitorImpl<MallocBugVisitor> {
    // The symbol representing the memory allocated by malloc.
    SymbolRef Sym;

  public:
    MallocBugVisitor(SymbolRef S) : Sym(S) {}
    void Profile(llvm::FoldingSetNodeID &ID) const override {
      // This presumably exists to ensure that this node is not folded into
      // another due to being considered equivalent.
      static int X = 0;
      ID.AddPointer(&X);
      ID.AddPointer(Sym);
    }

    std::shared_ptr<PathDiagnosticPiece> VisitNode(const ExplodedNode *N,
                                                   const ExplodedNode *PrevN,
                                                   BugReporterContext &BRC,
                                                   BugReport &BR) override;
  };
};
} // end anonymous namespace

// Register a map from pointer addresses to their state.
REGISTER_MAP_WITH_PROGRAMSTATE(AddressMap, SymbolRef, AllocState)

AllocFreeChecker::AllocFreeChecker() {
  AllocDeallocMismatchBugType.reset(
      new BugType(this, "Alloc-dealloc mismatch", categories::MemoryError));
  DoubleFreeBugType.reset(
      new BugType(this, "Double free", categories::MemoryError));
  LeakBugType.reset(new BugType(this, "Memory leak", categories::MemoryError));
  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  LeakBugType->setSuppressOnSink(true);
}

AllocationFamily getWmemFamily(const CallEvent &Call, CheckerContext &C) {
  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return AF_None;

  if (ArgE->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNotNull))
    return AF_WmemNullScope;

  if (const CallExpr *CE = dyn_cast<CallExpr>(ArgE)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef DeallocatorName = FD->getName();
      if (DeallocatorName == "wmem_epan_scope") {
        return AF_WmemEpanScope;
      }
      if (DeallocatorName == "wmem_file_scope") {
        return AF_WmemFileScope;
      }
      if (DeallocatorName == "wmem_packet_scope") {
        return AF_WmemPacketScope;
      }
    }
    // Unknown scope
    return AF_WmemOther;
  }

  // Unknown type (perhaps pinfo->pool?)
  return AF_WmemOther;
}

AllocationFamily getAllocFamily(const CallEvent &Call, CheckerContext &C) {
  if (Call.isGlobalCFunction("g_malloc") ||
      Call.isGlobalCFunction("g_malloc0") ||
      Call.isGlobalCFunction("g_memdup") ||
      Call.isGlobalCFunction("g_strdup") ||
      Call.isGlobalCFunction("g_strndup") ||
      Call.isGlobalCFunction("g_realloc")) {
    return AF_Glib;
  } else if (Call.isGlobalCFunction("g_strsplit") ||
             Call.isGlobalCFunction("g_strdupv")) {
    return AF_GlibStringVector;
  } else if (Call.isGlobalCFunction("wmem_alloc") ||
             Call.isGlobalCFunction("wmem_alloc0") ||
             Call.isGlobalCFunction("wmem_realloc") ||
             Call.isGlobalCFunction("wmem_strdup") ||
             Call.isGlobalCFunction("wmem_strndup") ||
             Call.isGlobalCFunction("wmem_strdup_printf") ||
             Call.isGlobalCFunction("wmem_strdup_vprintf") ||
             Call.isGlobalCFunction("wmem_strconcat") ||
             Call.isGlobalCFunction("wmem_strjoin") ||
             Call.isGlobalCFunction("wmem_strjoinv") ||
             Call.isGlobalCFunction("wmem_strsplit") ||
             Call.isGlobalCFunction("wmem_ascii_strdown")) {
    return getWmemFamily(Call, C);
  }
  return AF_None;
}

AllocationFamily getDeallocFamily(const CallEvent &Call, CheckerContext &C) {
  if (Call.isGlobalCFunction("g_free") || Call.isGlobalCFunction("g_realloc")) {
    return AF_Glib;
  } else if (Call.isGlobalCFunction("g_strfreev")) {
    return AF_GlibStringVector;
  } else if (Call.isGlobalCFunction("wmem_free") ||
             Call.isGlobalCFunction("wmem_realloc")) {
    return getWmemFamily(Call, C);
  }
  return AF_None;
}

void printExpectedDeallocName(raw_ostream &os, AllocationFamily family) {
  switch (family) {
  case AF_Glib:
    os << "g_free";
    break;
  case AF_GlibStringVector:
    os << "g_strfreev";
    break;
  case AF_WmemNullScope:
    os << "wmem_free(NULL, ...)";
    break;
  case AF_WmemEpanScope:
    os << "wmem_free(wmem_epan_scope(), ...)";
    break;
  case AF_WmemFileScope:
    os << "wmem_free(wmem_file_scope(), ...)";
    break;
  case AF_WmemPacketScope:
    os << "wmem_free(wmem_packet_scope(), ...)";
    break;
  case AF_WmemOther:
    os << "wmem_free";
    break;
  case AF_None:
    llvm_unreachable("suspicious argument");
  }
}

/// Process alloc
void AllocFreeChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || Call.getNumArgs() == 0)
    return;

  AllocationFamily family = getAllocFamily(Call, C);
  if (family != AF_None) {
    SymbolRef Address = Call.getReturnValue().getAsSymbol();
    if (!Address)
      return;

    // Generate the next transition (an edge in the exploded graph).
    ProgramStateRef State = C.getState();
    State = State->set<AddressMap>(Address, AllocState::getAllocated(family));
    C.addTransition(State);
  }
}

void AllocFreeChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || Call.getNumArgs() == 0)
    return;

  AllocationFamily family = getDeallocFamily(Call, C);
  if (family != AF_None) {
    unsigned pointerParam = isWmemAllocationFamily(family) ? 1 : 0;
    if (Call.getNumArgs() < pointerParam + 1)
      return;

    SymbolRef Address = Call.getArgSVal(pointerParam).getAsSymbol();
    if (!Address)
      return;

    // Check if the pointer was indeed allocated.
    ProgramStateRef State = C.getState();
    const AllocState *AS = State->get<AddressMap>(Address);
    if (AS) {
      if (AS->isFreed()) {
        reportDoubleFree(Address, Call, C, "memory was freed before");
        return;
      } else if (!AS->isFamily(family)) {
        reportAllocDeallocMismatch(Address, Call, C, AS->getAllocationFamily());
        return;
      }
    }

    // Generate the next transition (an edge in the exploded graph).
    State = State->set<AddressMap>(Address, AllocState::getFreed(family));
    C.addTransition(State);
  }
}

static bool isLeaked(SymbolRef Sym, const AllocState &AS, bool IsSymDead,
                     ProgramStateRef State) {
  if (IsSymDead && (AS.isAllocated() && !AS.isManagedDeallocation())) {
    // If a symbol is NULL, no memory was allocated (e.g. g_strdup(NULL)).
    // A symbol should only be considered leaked if it is non-null.
    ConstraintManager &CMgr = State->getConstraintManager();
    ConditionTruthVal AllocFailed = CMgr.isNull(State, Sym);
    return !AllocFailed.isConstrainedTrue();
  }
  return false;
}

void AllocFreeChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolVector LeakedAddresses;
  AddressMapTy TrackedAddresses = State->get<AddressMap>();
  for (AddressMapTy::iterator I = TrackedAddresses.begin(),
                              E = TrackedAddresses.end();
       I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SymReaper.isDead(Sym);

    if (isLeaked(Sym, I->second, IsSymDead, State))
      LeakedAddresses.push_back(Sym);

    if (IsSymDead)
      State = State->remove<AddressMap>(Sym);
  }
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;
  // TODO this sometimes points to the next node (for "p = identityFunction(p)")
  reportLeaks(LeakedAddresses, C, N);
}

void AllocFreeChecker::reportAllocDeallocMismatch(
    SymbolRef AddressSym, const CallEvent &Call, CheckerContext &C,
    AllocationFamily family) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();

  // If we have already reached this node on another path, return.
  if (!ErrNode)
    return;

  SmallString<100> buf;
  llvm::raw_svector_ostream os(buf);

  os << "Memory is expected to be deallocated by ";
  printExpectedDeallocName(os, family);

  // Generate a bug report.
  auto R = llvm::make_unique<BugReport>(*AllocDeallocMismatchBugType, os.str(),
                                        ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(AddressSym);
  R->addVisitor(llvm::make_unique<MallocBugVisitor>(AddressSym));
  C.emitReport(std::move(R));
}

void AllocFreeChecker::reportDoubleFree(SymbolRef AddressSym,
                                        const CallEvent &Call,
                                        CheckerContext &C,
                                        const char *msg) const {
  // We reached a bug, stop exploring the path here by generaring a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();

  // If we have already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate a bug report.
  auto R = llvm::make_unique<BugReport>(*DoubleFreeBugType, msg, ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(AddressSym);
  R->addVisitor(llvm::make_unique<MallocBugVisitor>(AddressSym));
  C.emitReport(std::move(R));
}

void AllocFreeChecker::reportLeaks(ArrayRef<SymbolRef> LeakedAddresses,
                                   CheckerContext &C,
                                   ExplodedNode *ErrNode) const {
  for (SymbolRef LeakedAddress : LeakedAddresses) {
    auto R = llvm::make_unique<BugReport>(*LeakBugType, "Memory leak", ErrNode);
    R->markInteresting(LeakedAddress);
    R->addVisitor(llvm::make_unique<MallocBugVisitor>(LeakedAddress));
    C.emitReport(std::move(R));
  }
}

bool guaranteedNotToFreeMemory(const CallEvent &Call) {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  StringRef FName = FD->getName();
  // Assume that GLib functions (g_*) and wmem functions (wmem_*) do not release
  // or change the address (that will be handled in PostCall).
  return FName.startswith("g_free") || FName.startswith("g_realloc") ||
         FName.startswith("wmem_free") || FName.startswith("wmem_realloc");
}

// If the pointer we are tracking escaped, do not track the symbol as
// we cannot reason about it anymore.
ProgramStateRef AllocFreeChecker::checkPointerEscape(
    ProgramStateRef State, const InvalidatedSymbols &Escaped,
    const CallEvent *Call, PointerEscapeKind Kind) const {
  // If this memory will not be freed, keep the memory in the state.
  if (Kind == PSK_DirectEscapeOnCall && guaranteedNotToFreeMemory(*Call)) {
    return State;
  }

  for (InvalidatedSymbols::const_iterator I = Escaped.begin(),
                                          E = Escaped.end();
       I != E; ++I) {
    SymbolRef Sym = *I;

    // The symbol escaped. Optimistically, assume that the corresponding memory
    // will be deallocated somewhere else.
    State = State->remove<AddressMap>(Sym);
  }
  return State;
}

std::shared_ptr<PathDiagnosticPiece>
AllocFreeChecker::MallocBugVisitor::VisitNode(const ExplodedNode *N,
                                              const ExplodedNode *PrevN,
                                              BugReporterContext &BRC,
                                              BugReport &BR) {
  ProgramStateRef state = N->getState();
  ProgramStateRef statePrev = PrevN->getState();

  const AllocState *AS = state->get<AddressMap>(Sym);
  const AllocState *ASPrev = statePrev->get<AddressMap>(Sym);
  if (!AS)
    return nullptr;

  const Stmt *S = PathDiagnosticLocation::getStmt(N);
  if (!S)
    return nullptr;

  const char *Msg = nullptr;
  // Mark new memory allocations (transition unknown/unallocated -> allocated)
  if ((!ASPrev || !ASPrev->isAllocated()) && AS->isAllocated()) {
    Msg = "Memory is allocated";
  }
  // Mark freeing of memory (transition unknown/allocated -> freed)
  if ((!ASPrev || ASPrev->isAllocated()) && AS->isFreed()) {
    Msg = "Memory is released";
  }
  if (!Msg)
    return nullptr;

  // Generate the extra diagnostic.
  PathDiagnosticLocation Pos(S, BRC.getSourceManager(),
                             N->getLocationContext());
  return std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
}

#if 0
void ento::registerAllocFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<AllocFreeChecker>();
}
#endif

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<AllocFreeChecker>(
      "alpha.AllocFree",
      "Detects mismatches between memory allocations and deallocations");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
