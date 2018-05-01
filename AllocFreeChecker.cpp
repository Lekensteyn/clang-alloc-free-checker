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
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
};

class AllocFreeChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols> {
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
}

AllocationFamily getWmemFamily(const CallEvent &Call) {
  // TODO actually match the expected scope
  return AF_WmemNullScope;
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
             Call.isGlobalCFunction("wmem_strdup") ||
             Call.isGlobalCFunction("wmem_strndup") ||
             Call.isGlobalCFunction("wmem_strdup_printf") ||
             Call.isGlobalCFunction("wmem_strdup_vprintf") ||
             Call.isGlobalCFunction("wmem_strconcat") ||
             Call.isGlobalCFunction("wmem_strjoin") ||
             Call.isGlobalCFunction("wmem_strjoinv") ||
             Call.isGlobalCFunction("wmem_strsplit") ||
             Call.isGlobalCFunction("wmem_ascii_strdown")) {
    return getWmemFamily(Call);
  }
  return AF_None;
}

AllocationFamily getDeallocFamily(const CallEvent &Call) {
  if (Call.isGlobalCFunction("g_free") || Call.isGlobalCFunction("g_realloc")) {
    return AF_Glib;
  } else if (Call.isGlobalCFunction("g_strfreev")) {
    return AF_GlibStringVector;
  } else if (Call.isGlobalCFunction("wmem_free")) {
    return getWmemFamily(Call);
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
  if (!Call.isGlobalCFunction())
    return;

  AllocationFamily family = getAllocFamily(Call);
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
  if (!Call.isGlobalCFunction())
    return;

  AllocationFamily family = getDeallocFamily(Call);
  if (family != AF_None) {
    unsigned pointerParam = isWmemAllocationFamily(family) ? 1 : 0;
    // TODO realloc has an additional parameter
    if (Call.getNumArgs() != pointerParam + 1)
      return;

    SymbolRef Address = Call.getArgSVal(pointerParam).getAsSymbol();
    if (!Address)
      return;

    // Check if the pointer was indeed allocated.
    ProgramStateRef State = C.getState();
    const AllocState *SS = State->get<AddressMap>(Address);
    if (SS) {
      if (SS->isFreed()) {
        reportDoubleFree(Address, Call, C, "memory was freed before");
        return;
      } else if (!SS->isFamily(family)) {
        reportAllocDeallocMismatch(Address, Call, C, SS->getAllocationFamily());
        return;
      }
    }

    // Generate the next transition (an edge in the exploded graph).
    State = State->set<AddressMap>(Address, AllocState::getFreed(family));
    C.addTransition(State);
  }
}

static bool isLeaked(SymbolRef Sym, const AllocState &SS, bool IsSymDead) {
  if (IsSymDead && (SS.isAllocated() && !SS.isManagedDeallocation())) {
    return true;
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

    if (isLeaked(Sym, I->second, IsSymDead))
      LeakedAddresses.push_back(Sym);

    if (IsSymDead)
      State = State->remove<AddressMap>(Sym);
  }
  ExplodedNode *N = C.addTransition(State);
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
  C.emitReport(std::move(R));
}

void AllocFreeChecker::reportLeaks(ArrayRef<SymbolRef> LeakedAddresses,
                                   CheckerContext &C,
                                   ExplodedNode *ErrNode) const {
  for (SymbolRef LeakedAddress : LeakedAddresses) {
    auto R = llvm::make_unique<BugReport>(*LeakBugType, "Memory leak", ErrNode);
    R->markInteresting(LeakedAddress);
    C.emitReport(std::move(R));
  }
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
