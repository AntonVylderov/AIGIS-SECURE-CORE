//! Transaction amount verification using Z3 theorem prover.
//! Global solver is reused to avoid expensive reinitialisation.

use once_cell::sync::Lazy;
use z3::{Config, Context, Solver, ast::Int};

static Z3: Lazy<(Context, Solver)> = Lazy::new(|| {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    (ctx, solver)
});

/// Returns `true` if amount is strictly between 0 and 1_000_000.
pub fn verify_transaction_amount(amount: u64) -> bool {
    let (ctx, solver) = &*Z3;
    let x = Int::from_u64(ctx, amount);
    let zero = Int::from_u64(ctx, 0);
    let limit = Int::from_u64(ctx, 1_000_000);

    let violation = x.le(&zero).or(&x.ge(&limit));
    solver.push();
    solver.assert(&violation);
    let result = solver.check();
    solver.pop(1);
    matches!(result, z3::SatResult::Unsat)
}
