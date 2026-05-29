# Complexity Reduction — Compact Remediation Guide

## What is Complexity Reduction?

Complexity Reduction is the systematic refactoring of high-complexity code (cyclomatic complexity >10) into smaller, focused functions using Extract Method, Guard Clauses, and Strategy Pattern to reduce defect rates and improve maintainability.

## Related OWASP

- **Primary**: A04 - Insecure Design (complex code obscures security logic and increases attack surface)
- **Secondary**: A01 - Broken Access Control (nested authorization logic is error-prone and hard to audit)

## Types/Patterns of Complexity

- **High Cyclomatic Complexity**: Functions with >10 decision points (if/else, loops, switch, &&, ||) correlate with 2-3x higher bug rates
- **Deep Nesting**: Code with >3 levels of indentation is hard to understand and review
- **Long Functions**: Functions >50 lines with mixed concerns and multiple responsibilities
- **Long Parameter Lists**: Functions with >4 parameters indicate insufficient abstraction
- **Large Switch Statements**: Branching logic that violates Open/Closed Principle

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Complexity 18, deep nesting, mixed concerns
function processOrder(order: any, user: any, inventory: any) {
  if (order.status === 'pending') {
    if (user.role === 'admin' || user.id === order.userId) {
      if (inventory.has(order.itemId)) {
        if (inventory.quantity >= order.quantity) {
          if (order.paymentMethod === 'credit_card') {
            if (user.creditCard && !user.creditCard.expired) {
              // actual processing logic buried 6 levels deep
              return chargeCard(user.creditCard, order.total);
            } else {
              return { error: 'Invalid payment method' };
            }
          } else if (order.paymentMethod === 'paypal') {
            // duplicate payment logic
          }
        } else {
          return { error: 'Insufficient inventory' };
        }
      } else {
        return { error: 'Item not found' };
      }
    } else {
      return { error: 'Unauthorized' };
    }
  } else {
    return { error: 'Invalid status' };
  }
}
// Attack: Security logic hidden in nested conditions makes authorization bypass easier
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Complexity ≤3 per function with clear separation
import { z } from 'zod';

// ✅ Input validation extracted
const orderSchema = z.object({
  status: z.literal('pending'),
  userId: z.string().uuid(),
  itemId: z.string().uuid(),
  quantity: z.number().int().positive(),
  paymentMethod: z.enum(['credit_card', 'paypal'])
});

// ✅ Authorization extracted (complexity: 2)
function canProcessOrder(user: User, order: Order): boolean {
  return user.role === 'admin' || user.id === order.userId;
}

// ✅ Inventory check extracted (complexity: 2)
function hasInventory(inventory: Inventory, itemId: string, quantity: number): boolean {
  return inventory.has(itemId) && inventory.get(itemId).quantity >= quantity;
}

// ✅ Payment processing extracted (complexity: 2)
async function processPayment(method: string, user: User, amount: number): Promise<Result> {
  const strategies: Record<string, PaymentProcessor> = {
    credit_card: new CreditCardProcessor(),
    paypal: new PayPalProcessor()
  };
  return strategies[method].charge(user, amount);
}

// ✅ Main function uses guard clauses (complexity: 5, down from 18)
export async function processOrder(order: unknown, user: User, inventory: Inventory) {
  // Guard clauses: fail fast on validation errors
  const validOrder = orderSchema.parse(order);
  if (!canProcessOrder(user, validOrder)) throw new Error('Unauthorized');
  if (!hasInventory(inventory, validOrder.itemId, validOrder.quantity)) {
    throw new Error('Insufficient inventory');
  }

  return processPayment(validOrder.paymentMethod, user, validOrder.total);
}

// ✅ Key Patterns:
// 1. Extract Method: Split one complex function into 4 focused functions
// 2. Guard Clauses: Use early returns to reduce nesting from 6 to 1 level
// 3. Strategy Pattern: Replace if-else chain with lookup table for payment methods
// 4. Single Responsibility: Each function validates or processes one thing
// 5. Complexity ≤3: All extracted functions have cyclomatic complexity ≤3
```

## Human Review Checklist

- [ ] **Cyclomatic Complexity** — All functions have complexity ≤10, critical functions ≤8 (use ts-complex or SonarQube to measure, verify no function exceeds threshold, refactor violators using Extract Method)

- [ ] **Nesting Depth** — No code deeper than 3 levels of indentation (grep for deeply nested blocks, apply guard clauses with early returns to flatten structure, ensure happy path has minimal indentation)

- [ ] **Function Length** — No functions exceed 50 lines (validate each function does ONE thing, extract helper functions for complex operations, ensure descriptive names)

- [ ] **Separation of Concerns** — Validation, authorization, business logic, and data access are in separate functions (verify no mixing of concerns, test each function independently, ensure clear boundaries)

- [ ] **Pattern Application** — Complex conditionals use appropriate patterns (Strategy for switch statements, Decompose Conditional for complex boolean expressions, Polymorphism for type-based behavior)

- [ ] **Behavior Preservation** — All existing tests pass after refactoring, no changes to function signatures or return types (run full test suite, verify edge cases still handled, ensure error handling equivalent)

---

**Key Takeaway**: Functions with complexity >10 have exponentially higher defect rates; systematically refactor using Extract Method, Guard Clauses, and Strategy Pattern to reduce security risk and improve maintainability.
