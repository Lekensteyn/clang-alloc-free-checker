#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

// record symbols and the original allocation source.
typedef std::pair<SymbolRef, const ExplodedNode *> LeakInfo;
typedef SmallVector<LeakInfo, 2> LeakInfoVector;

// Groups allocation and deallocation functions.
enum AllocationFamily : unsigned {
  AF_None,
  AF_Glib,
  AF_GlibStringVector,
  AF_Wmem,
  AF_WmemStringVector
};

enum WmemAllocator : unsigned {
  WA_Invalid,
  WA_Null,
  WA_EpanScope,
  WA_FileScope,
  WA_PacketScope,
  WA_Other
};

bool isWmemAllocationFamily(AllocationFamily family) {
  return family == AF_Wmem || family == AF_WmemStringVector;
}

class AllocState {
  enum Kind : unsigned { Allocated, Freed };
  unsigned K : 1;
  unsigned Family : 28;
  unsigned WA : 3;

  AllocState(Kind InK, AllocationFamily family, WmemAllocator wa)
      : K(InK), Family(family), WA(wa) {
    assert(family != AF_None);
    assert(isWmemAllocationFamily(family) ^ (WA == WA_Invalid));
  }

public:
  bool isAllocated() const { return K == Allocated; }
  bool isFreed() const { return K == Freed; }
  bool isFamily(AllocationFamily family) const { return Family == family; }
  AllocationFamily getAllocationFamily() const {
    return (AllocationFamily)Family;
  }
  bool isWmemAllocator(WmemAllocator wa) const { return WA == wa; }
  WmemAllocator getWmemAllocator() const { return (WmemAllocator)WA; }

  /// Returns true if this is scoped wmem-allocated memory that is automatically
  /// freed when the scope is left.
  bool isManagedDeallocation() const {
    return isWmemAllocationFamily((AllocationFamily)Family) && WA != WA_Null;
  }

  static AllocState getAllocated(AllocationFamily family, WmemAllocator wa) {
    return AllocState(Allocated, family, wa);
  }
  static AllocState getFreed(AllocationFamily family, WmemAllocator wa) {
    return AllocState(Freed, family, wa);
  }

  bool operator==(const AllocState &X) const {
    return X.K == K && X.Family == Family && X.WA == WA;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddInteger(Family);
    ID.AddInteger(WA);
  }
};

class AllocFreeChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols,
                     check::PointerEscape> {
  std::unique_ptr<BugType> AllocDeallocMismatchBugType;
  std::unique_ptr<BugType> DoubleFreeBugType;
  std::unique_ptr<BugType> LeakBugType;

  void reportAllocDeallocMismatch(SymbolRef AddressSym, const CallEvent &Call,
                                  CheckerContext &C, AllocationFamily family,
                                  WmemAllocator wmemAllocator) const;

  void reportDoubleFree(SymbolRef AddressSym, const CallEvent &Call,
                        CheckerContext &C, const char *msg) const;

  void reportLeak(SymbolRef AddressSym, CheckerContext &C, bool potential,
                  ExplodedNode *ErrNode, const ExplodedNode *AllocNode) const;

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

WmemAllocator getWmemAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return WA_Invalid;

  if (ArgE->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNotNull))
    return WA_Null;

  ArgE = ArgE->IgnoreParenCasts();
  if (const CallExpr *CE = dyn_cast<CallExpr>(ArgE)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef DeallocatorName = FD->getName();
      if (DeallocatorName == "wmem_epan_scope") {
        return WA_EpanScope;
      }
      if (DeallocatorName == "wmem_file_scope") {
        return WA_FileScope;
      }
      if (DeallocatorName == "wmem_packet_scope") {
        return WA_PacketScope;
      }
    }
    // Unknown scope
    return WA_Other;
  }

  // Unknown type (perhaps pinfo->pool?)
  return WA_Other;
}

AllocationFamily getAllocFamily(const CallEvent &Call) {
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
             Call.isGlobalCFunction("wmem_ascii_strdown")) {
    return AF_Wmem;
  } else if (Call.isGlobalCFunction("wmem_strsplit")) {
    return AF_WmemStringVector;
  }
  return AF_None;
}

AllocationFamily getDeallocFamily(const CallEvent &Call) {
  if (Call.isGlobalCFunction("g_free") || Call.isGlobalCFunction("g_realloc")) {
    return AF_Glib;
  } else if (Call.isGlobalCFunction("g_strfreev")) {
    return AF_GlibStringVector;
  } else if (Call.isGlobalCFunction("wmem_free") ||
             Call.isGlobalCFunction("wmem_realloc")) {
    return AF_Wmem;
  }
  return AF_None;
}

void printExpectedDeallocName(raw_ostream &os, AllocationFamily family,
                              WmemAllocator wmemAllocator) {
  switch (family) {
  case AF_Glib:
    os << "g_free";
    break;
  case AF_GlibStringVector:
    os << "g_strfreev";
    break;
  case AF_Wmem:
  case AF_WmemStringVector: // TODO find better API for wmem_strsplit
    switch (wmemAllocator) {
    case WA_Null:
      os << "wmem_free(NULL, ...)";
      break;
    case WA_EpanScope:
      os << "wmem_free(wmem_epan_scope(), ...)";
      break;
    case WA_FileScope:
      os << "wmem_free(wmem_file_scope(), ...)";
      break;
    case WA_PacketScope:
      os << "wmem_free(wmem_packet_scope(), ...)";
      break;
    case WA_Other:
      os << "wmem_free";
      break;
    case WA_Invalid:
      llvm_unreachable("suspicious wmem allocator argument");
    }
    break;
  case AF_None:
    llvm_unreachable("suspicious argument");
  }
}

const ExplodedNode *getAllocationSite(const ExplodedNode *N, SymbolRef Sym) {
  const LocationContext *LeakContext = N->getLocationContext();
  // Walk the ExplodedGraph backwards and find the first node that referred to
  // the tracked symbol.
  const ExplodedNode *AllocNode = N;
  while (N) {
    ProgramStateRef State = N->getState();
    if (!State->get<AddressMap>(Sym))
      break;

    // Only consider allocations in the same function, or higher in the call
    // chain.
    const LocationContext *NContext = N->getLocationContext();
    if (NContext == LeakContext || NContext->isParentOf(LeakContext))
      AllocNode = N;
    N = N->pred_empty() ? nullptr : *(N->pred_begin());
  }
  return AllocNode;
}

/// Process alloc
void AllocFreeChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || Call.getNumArgs() == 0)
    return;

  AllocationFamily family = getAllocFamily(Call);
  if (family != AF_None) {
    SymbolRef Address = Call.getReturnValue().getAsSymbol();
    if (!Address)
      return;

    WmemAllocator WA =
        isWmemAllocationFamily(family) ? getWmemAllocator(Call, C) : WA_Invalid;

    // Generate the next transition (an edge in the exploded graph).
    ProgramStateRef State = C.getState();
    State =
        State->set<AddressMap>(Address, AllocState::getAllocated(family, WA));
    C.addTransition(State);
  }
}

void AllocFreeChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || Call.getNumArgs() == 0)
    return;

  AllocationFamily family = getDeallocFamily(Call);
  if (family != AF_None) {
    unsigned pointerParam = isWmemAllocationFamily(family) ? 1 : 0;
    if (Call.getNumArgs() < pointerParam + 1)
      return;

    SymbolRef Address = Call.getArgSVal(pointerParam).getAsSymbol();
    if (!Address)
      return;

    WmemAllocator WA =
        isWmemAllocationFamily(family) ? getWmemAllocator(Call, C) : WA_Invalid;

    // Check if the pointer was indeed allocated.
    ProgramStateRef State = C.getState();
    const AllocState *AS = State->get<AddressMap>(Address);
    if (AS) {
      // Special case: wmem_strsplit currently does not have a dedicated free
      // function. Treat wmem_free with the correct scope as its free function.
      if (AS->isFamily(AF_WmemStringVector) && family == AF_Wmem) {
        family = AF_WmemStringVector;
      }

      if (AS->isFreed()) {
        reportDoubleFree(Address, Call, C, "memory was freed before");
        return;
      } else if (!AS->isFamily(family)) {
        reportAllocDeallocMismatch(Address, Call, C, AS->getAllocationFamily(),
                                   AS->getWmemAllocator());
        return;
      } else if (isWmemAllocationFamily(family) && !AS->isWmemAllocator(WA)) {
        reportAllocDeallocMismatch(Address, Call, C, AS->getAllocationFamily(),
                                   AS->getWmemAllocator());
        return;
      } else if (family == AF_WmemStringVector) {
        // wmem_packet_scope is quite transient, assume that other scopes are
        // not safe and indicate a memleak.
        if (!AS->isWmemAllocator(WA_PacketScope)) {
          ExplodedNode *N = C.generateNonFatalErrorNode(State);
          const ExplodedNode *AllocNode = getAllocationSite(N, Address);
          reportLeak(Address, C, true, N, AllocNode);
        }
      }
    }

    // Generate the next transition (an edge in the exploded graph).
    State = State->set<AddressMap>(Address, AllocState::getFreed(family, WA));
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
  LeakInfoVector LeakInfos;
  AddressMapTy TrackedAddresses = State->get<AddressMap>();
  for (AddressMapTy::iterator I = TrackedAddresses.begin(),
                              E = TrackedAddresses.end();
       I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SymReaper.isDead(Sym);

    if (isLeaked(Sym, I->second, IsSymDead, State)) {
      // Check here for the original node that allocated the memory, this check
      // will not always be possible when it the symbol is removed from the
      // state, see below.
      const ExplodedNode *AllocNode =
          getAllocationSite(C.getPredecessor(), Sym);
      LeakInfos.emplace_back(Sym, AllocNode);
    }

    if (IsSymDead)
      State = State->remove<AddressMap>(Sym);
  }
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;
  // TODO this sometimes points to the next node (for "p = identityFunction(p)")
  for (LeakInfo Leaked : LeakInfos) {
    reportLeak(Leaked.first, C, false, N, Leaked.second);
  }
}

void AllocFreeChecker::reportAllocDeallocMismatch(
    SymbolRef AddressSym, const CallEvent &Call, CheckerContext &C,
    AllocationFamily family, WmemAllocator wmemAllocator) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();

  // If we have already reached this node on another path, return.
  if (!ErrNode)
    return;

  SmallString<100> buf;
  llvm::raw_svector_ostream os(buf);

  os << "Memory is expected to be deallocated by ";
  printExpectedDeallocName(os, family, wmemAllocator);

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

void AllocFreeChecker::reportLeak(SymbolRef AddressSym, CheckerContext &C,
                                  bool potential, ExplodedNode *ErrNode,
                                  const ExplodedNode *AllocNode) const {
  // Most bug reports are cached at the location where they occurred.
  // With leaks, we want to unique them by the location where they were
  // allocated, and only report a single path.
  PathDiagnosticLocation LocUsedForUniqueing;
  const Stmt *AllocationStmt = PathDiagnosticLocation::getStmt(AllocNode);
  if (AllocationStmt)
    LocUsedForUniqueing = PathDiagnosticLocation::createBegin(
        AllocationStmt, C.getSourceManager(), AllocNode->getLocationContext());

  auto R = llvm::make_unique<BugReport>(
      *LeakBugType, potential ? "Potential memory leak" : "Memory leak",
      ErrNode, LocUsedForUniqueing, AllocNode->getLocationContext()->getDecl());
  R->markInteresting(AddressSym);
  R->addVisitor(llvm::make_unique<MallocBugVisitor>(AddressSym));
  C.emitReport(std::move(R));
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
