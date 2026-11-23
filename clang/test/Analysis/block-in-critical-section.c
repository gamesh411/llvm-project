// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,unix.BlockInCriticalSection \
// RUN:   -analyzer-output text \
// RUN:   -verify %s

// This should not crash
int (*a)(void);
void b(void) { a(); }

unsigned int sleep(unsigned int seconds);

// XNU
typedef int boolean_t;
typedef struct { int opaque; } lck_mtx_t;
typedef struct { int opaque; } lck_rw_t;

void lck_mtx_lock(lck_mtx_t *lck);
boolean_t lck_mtx_try_lock(lck_mtx_t *lck);
void lck_mtx_unlock(lck_mtx_t *lck);
void lck_rw_lock_exclusive(lck_rw_t *lck);
void lck_rw_lock_shared(lck_rw_t *lck);
boolean_t lck_rw_try_lock_exclusive(lck_rw_t *lck);
boolean_t lck_rw_try_lock_shared(lck_rw_t *lck);
void lck_rw_unlock_exclusive(lck_rw_t *lck);
void lck_rw_unlock_shared(lck_rw_t *lck);
unsigned int lck_rw_done(lck_rw_t *lck);

// Fuchsia
typedef int spin_lock_t;
typedef int spin_lock_saved_state_t;
typedef int sync_mutex_t;
typedef int zx_status_t;
typedef long zx_instant_mono_t;

void spin_lock(spin_lock_t *lock);
int spin_trylock(spin_lock_t *lock);
void spin_unlock(spin_lock_t *lock);
void spin_lock_save(spin_lock_t *lock, spin_lock_saved_state_t *statep,
                    int flags);
void spin_unlock_restore(spin_lock_t *lock, spin_lock_saved_state_t old_state,
                         int flags);
void sync_mutex_lock(sync_mutex_t *mutex);
void sync_mutex_lock_with_waiter(sync_mutex_t *mutex);
zx_status_t sync_mutex_trylock(sync_mutex_t *mutex);
zx_status_t sync_mutex_timedlock(sync_mutex_t *mutex, zx_instant_mono_t deadline);
void sync_mutex_unlock(sync_mutex_t *mutex);

void xnu_mtx(lck_mtx_t *m) {
  lck_mtx_lock(m); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_mtx_unlock(m);
  sleep(1); // no-warning
}

void xnu_mtx_try(lck_mtx_t *m) {
  lck_mtx_try_lock(m); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_mtx_unlock(m);
  sleep(1); // no-warning
}

void xnu_rw_exclusive(lck_rw_t *rw) {
  lck_rw_lock_exclusive(rw); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_rw_unlock_exclusive(rw);
  sleep(1); // no-warning
}

void xnu_rw_shared(lck_rw_t *rw) {
  lck_rw_lock_shared(rw); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_rw_unlock_shared(rw);
  sleep(1); // no-warning
}

void xnu_rw_try_exclusive(lck_rw_t *rw) {
  lck_rw_try_lock_exclusive(rw); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_rw_unlock_exclusive(rw);
  sleep(1); // no-warning
}

void xnu_rw_try_shared(lck_rw_t *rw) {
  lck_rw_try_lock_shared(rw); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_rw_unlock_shared(rw);
  sleep(1); // no-warning
}

void xnu_rw_done_exclusive(lck_rw_t *rw) {
  lck_rw_lock_exclusive(rw);
  lck_rw_done(rw);
  sleep(1); // no-warning
}

void xnu_rw_done_shared(lck_rw_t *rw) {
  lck_rw_lock_shared(rw);
  lck_rw_done(rw);
  sleep(1); // no-warning
}

void fuchsia_spin(spin_lock_t *l) {
  spin_lock(l); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  spin_unlock(l);
  sleep(1); // no-warning
}

void fuchsia_spin_try(spin_lock_t *l) {
  spin_trylock(l); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  spin_unlock(l);
  sleep(1); // no-warning
}

void fuchsia_spin_save(spin_lock_t *l) {
  spin_lock_saved_state_t state;
  spin_lock_save(l, &state, 0); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  spin_unlock_restore(l, state, 0);
  sleep(1); // no-warning
}

void fuchsia_sync_mutex(sync_mutex_t *m) {
  sync_mutex_lock(m); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  sync_mutex_unlock(m);
  sleep(1); // no-warning
}

void fuchsia_sync_mutex_with_waiter(sync_mutex_t *m) {
  sync_mutex_lock_with_waiter(m); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  sync_mutex_unlock(m);
  sleep(1); // no-warning
}

void fuchsia_sync_mutex_try(sync_mutex_t *m) {
  sync_mutex_trylock(m); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  sync_mutex_unlock(m);
  sleep(1); // no-warning
}

void fuchsia_sync_mutex_timed(sync_mutex_t *m) {
  sync_mutex_timedlock(m, 100); // expected-note {{Entering critical section here}}
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  sync_mutex_unlock(m);
  sleep(1); // no-warning
}

void unlock_ends_only_its_own_section(lck_mtx_t *m, spin_lock_t *l) {
  lck_mtx_lock(m); // expected-note {{Entering critical section here}}
  spin_lock(l);
  spin_unlock(l);
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
  lck_mtx_unlock(m);
}
