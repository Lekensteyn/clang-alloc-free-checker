#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;

class AllocState {
  enum Kind { Allocated, Freed, ListAllocated, ListFreed } K;
  AllocState(Kind InK) : K(InK) {}

public:
  bool isAllocated() const { return K == Allocated; }
  bool isListAllocated() const { return K == ListAllocated; }
  bool isFreed() const { return K == Freed; }
  bool isListFreed() const { return K == ListFreed; }

  static AllocState getAllocated() { return AllocState(Allocated); }
  static AllocState getFreed() { return AllocState(Freed); }
  static AllocState getListAllocated() { return AllocState(ListAllocated); }
  static AllocState getListFreed() { return AllocState(ListFreed); }

  bool operator==(const AllocState &X) const { return X.K == K; }
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
};

class AllocFreeChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols> {
  std::unique_ptr<BugType> AllocDeallocMismatchBugType;
  std::unique_ptr<BugType> DoubleFreeBugType;
  std::unique_ptr<BugType> LeakBugType;

  void reportAllocDeallocMismatch(SymbolRef AddressSym, const CallEvent &Call,
                                  CheckerContext &C, const char *msg) const;

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
REGISTER_MAP_WITH_PROGRAMSTATE(AddressMap, SymbolRef, AllocState);

AllocFreeChecker::AllocFreeChecker() {
  AllocDeallocMismatchBugType.reset(
      new BugType(this, "Alloc-dealloc mismatch", categories::MemoryError));
  DoubleFreeBugType.reset(
      new BugType(this, "Double free", categories::MemoryError));
  LeakBugType.reset(new BugType(this, "Memory leak", categories::MemoryError));
}

bool isAllocFunction(const CallEvent &Call) {
  return Call.isGlobalCFunction("g_malloc") ||
         Call.isGlobalCFunction("g_malloc0") ||
         Call.isGlobalCFunction("g_realloc");
}

bool isListAllocFunction(const CallEvent &Call) {
  return Call.isGlobalCFunction("g_strsplit");
}

/// Process alloc
void AllocFreeChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  bool is_alloc = isAllocFunction(Call);
  bool is_list_alloc = !is_alloc && isListAllocFunction(Call);
  if (is_alloc || is_list_alloc) {
    SymbolRef Address = Call.getReturnValue().getAsSymbol();
    if (!Address)
      return;

    // Generate the next transition (an edge in the exploded graph).
    ProgramStateRef State = C.getState();
    State = State->set<AddressMap>(Address,
                                   is_alloc ? AllocState::getAllocated()
                                            : AllocState::getListAllocated());
    C.addTransition(State);
  }
}

void AllocFreeChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || Call.getNumArgs() != 1)
    return;

  bool is_dealloc = Call.isGlobalCFunction("g_free");
  bool is_list_dealloc = !is_dealloc && Call.isGlobalCFunction("g_strfreev");
  if (is_dealloc || is_list_dealloc) {
    SymbolRef Address = Call.getArgSVal(0).getAsSymbol();
    if (!Address)
      return;

    // Check if the pointer was indeed allocated.
    ProgramStateRef State = C.getState();
    const AllocState *SS = State->get<AddressMap>(Address);
    if (SS) {
      if (is_dealloc) {
        if (SS->isFreed()) {
          reportDoubleFree(Address, Call, C, "memory was freed before");
          return;
        } else if (SS->isListAllocated()) {
          reportAllocDeallocMismatch(
              Address, Call, C, "list allocated, but freed as normal memory");
          return;
        } else if (!SS->isAllocated()) {
          reportAllocDeallocMismatch(Address, Call, C,
                                     "memory is not a list allocation");
          return;
        }
      } else if (is_list_dealloc) {
        if (SS->isListFreed()) {
          reportDoubleFree(Address, Call, C, "list was freed before");
          return;
        } else if (SS->isAllocated()) {
          reportAllocDeallocMismatch(
              Address, Call, C, "normal memory allocated, but freed as list");
          return;
        } else if (!SS->isListAllocated()) {
          reportAllocDeallocMismatch(Address, Call, C,
                                     "list was not allocated");
          return;
        }
      }
    }

    // Generate the next transition (an edge in the exploded graph).
    State = State->set<AddressMap>(Address, is_dealloc
                                                ? AllocState::getFreed()
                                                : AllocState::getListFreed());
    C.addTransition(State);
  }
}

static bool isLeaked(SymbolRef Sym, const AllocState &SS, bool IsSymDead) {
  if (IsSymDead && (SS.isAllocated() || SS.isListAllocated())) {
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

void AllocFreeChecker::reportAllocDeallocMismatch(SymbolRef AddressSym,
                                                  const CallEvent &Call,
                                                  CheckerContext &C,
                                                  const char *msg) const {
  // We reached a bug, stop exploring the path here by generaring a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();

  // If we have already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate a bug report.
  auto R =
      llvm::make_unique<BugReport>(*AllocDeallocMismatchBugType, msg, ErrNode);
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
