// The values `cut` starts from are named by where they live, such as
// `line->cells[0].width` and `grid->rows`, and the masked flags read as an
// expression whose type the trace gives.
struct cell { int width; unsigned flags; };
struct line { struct cell cells[4]; struct line *next; };
struct grid { struct line *lines; int rows; };

int cut(struct grid *grid, struct line *line, int *out) {
  if (grid->rows > 2 && line->cells[0].width == 1 &&
      (line->next->cells[1].flags & 4) != 0)
    out = 0;
  return *out;
}
