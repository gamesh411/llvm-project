void rcu_read_lock(void);
void rcu_read_unlock(void);
static inline void use_rcu() { rcu_read_lock(); rcu_read_unlock(); }


