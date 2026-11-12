// `lex` fills a token whose body the analyzer cannot see, so the token's kind
// after the call is a new value, and the path assumes it is 0.
struct Token {
  int Kind;
  int Len;
};
void lex(struct Token *Tok);

int parse(int *out) {
  struct Token Tok = {1, 0};
  lex(&Tok);
  if (Tok.Kind == 0)
    out = 0;
  return *out;
}
