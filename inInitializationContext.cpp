 StoreToImmutableChecker::isInitializationContext(const Stmt *S,
                                                      CheckerContext &C) const {
  // Check if this is a DeclStmt (variable declaration)
  if (isa<DeclStmt, DeclRefExpr>(S))
    return true;

  // Check if this is a CXXConstructExpr that's part of an initialization
  if (const CXXConstructExpr *CCE = dyn_cast<CXXConstructExpr>(S)) {
    // Look at the parent context to see if this is part of an initialization
    const Stmt *Parent = C.getLocationContext()->getParentMap().getParent(S);
    if (Parent && isa<DeclStmt>(Parent))
      return true;

    // Check if this is an elidable constructor call (copy/move constructor)
    if (CCE->isElidable())
      return true;
  }

  // Check if this is a MaterializeTemporaryExpr that's part of initialization
  if (isa<MaterializeTemporaryExpr>(S)) {
    const Stmt *Parent = C.getLocationContext()->getParentMap().getParent(S);
    if (Parent && isa<DeclStmt>(Parent))
      return true;
  }

  return false;
}
