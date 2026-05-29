# Single Responsibility Principle — Compact Remediation Guide

## What is the Single Responsibility Principle?

The Single Responsibility Principle (SRP) states that a class, function, or module should have one, and only one, reason to change; mixing responsibilities makes code harder to test, understand, and maintain as changes to one concern ripple through unrelated code.

## Related OWASP

- **Primary**: A01 - Broken Access Control (authorization logic mixed with business logic makes security audits difficult)
- **Secondary**: A03 - Injection (validation separated from data access enables focused security review)

## Types/Patterns of SRP Violations

- **God Functions**: Single function handling validation + business logic + persistence + formatting + side effects
- **Mixed Abstraction Levels**: High-level business logic mixed with low-level details (SQL queries, HTTP responses)
- **Routes with Business Logic**: Express/Koa handlers containing calculations, validations, and data transformations
- **Services with Data Access**: Business logic functions directly executing SQL queries
- **Cross-Cutting Concerns**: Logging, auth, error handling duplicated across functions instead of abstracted
- **Multiple Actors**: One class serving multiple stakeholders (CFO + CTO + Security Team) with different change reasons

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: God function handling 7 responsibilities
async function createUser(req: Request, res: Response) {
  // Responsibility 1: Request parsing
  const userData = req.body;

  // Responsibility 2: Validation
  if (!userData.email || !userData.email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  // Responsibility 3: Business logic
  const hashedPassword = bcrypt.hashSync(userData.password, 10);
  const user = { ...userData, password: hashedPassword, createdAt: new Date() };

  // Responsibility 4: Data access
  const result = await db.query(
    'INSERT INTO users (email, password) VALUES ($1, $2)',
    [user.email, user.password]
  );

  // Responsibility 5: Email notification
  await sendEmail(user.email, 'Welcome!', 'Thanks for signing up');

  // Responsibility 6: Logging
  logger.info(`User created: ${user.email}`);

  // Responsibility 7: Response formatting
  return res.json({ id: result.rows[0].id, email: user.email });
}

// Attack: Security review misses hardcoded bcrypt cost buried in 50-line function
// Attack: SQL injection possible because validation and data access are mixed
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Layered architecture with clear separation of concerns
import { z } from 'zod';

// ✅ Layer 1: Validation (single responsibility: validate input)
const createUserSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(12).max(128)
});

export function validateCreateUserInput(input: unknown) {
  return createUserSchema.parse(input);
}

// ✅ Layer 2: Domain logic (single responsibility: user business rules)
export function hashPassword(password: string): string {
  const BCRYPT_COST = 12; // Centralized security constant
  return bcrypt.hashSync(password, BCRYPT_COST);
}

export function createUserEntity(email: string, password: string): User {
  return {
    email,
    password: hashPassword(password),
    createdAt: new Date(),
    role: 'user'
  };
}

// ✅ Layer 3: Data access (single responsibility: persist user)
export class UserRepository {
  async create(user: User): Promise<string> {
    const result = await this.db.query<{ id: string }>(
      'INSERT INTO users (email, password, created_at, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [user.email, user.password, user.createdAt, user.role]
    );
    return result.rows[0].id;
  }
}

// ✅ Layer 4: Services (single responsibility: orchestrate user creation)
export class UserService {
  constructor(
    private userRepo: UserRepository,
    private emailService: EmailService,
    private logger: Logger
  ) {}

  async createUser(input: unknown): Promise<{ id: string; email: string }> {
    const validated = validateCreateUserInput(input);
    const user = createUserEntity(validated.email, validated.password);
    const userId = await this.userRepo.create(user);

    // Side effects (non-blocking)
    this.emailService.sendWelcome(user.email).catch(err =>
      this.logger.error('Email failed:', err)
    );
    this.logger.info(`User created: ${userId}`);

    return { id: userId, email: user.email };
  }
}

// ✅ Layer 5: HTTP layer (single responsibility: handle HTTP concerns)
export async function createUserHandler(req: Request, res: Response) {
  try {
    const result = await userService.createUser(req.body);
    res.status(201).json(result);
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Invalid input', details: err.errors });
    } else {
      logger.error('Create user failed:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

// ✅ Cross-cutting concerns extracted to middleware
export function withAuth(handler: RequestHandler): RequestHandler {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    return handler(req, res, next);
  };
}

export function withLogging(handler: RequestHandler): RequestHandler {
  return async (req, res, next) => {
    const start = Date.now();
    logger.info(`${req.method} ${req.path}`);
    await handler(req, res, next);
    logger.info(`${req.method} ${req.path} - ${Date.now() - start}ms`);
  };
}

// ✅ Key Patterns:
// 1. Layered architecture: HTTP → Service → Repository → Database (clear boundaries)
// 2. Single purpose functions: Each function validates OR transforms OR persists, never multiple
// 3. Dependency injection: Services receive dependencies via constructor (testable)
// 4. Cross-cutting concerns: Auth, logging extracted to middleware (composable)
// 5. Pure domain logic: Business rules have no framework dependencies (portable)
```

## Human Review Checklist

- [ ] **Single Purpose Functions** — Each function has exactly ONE clear responsibility described by its name (verify no function names with "and", ensure functions do validation OR logic OR persistence, test each function independently)

- [ ] **Layered Architecture** — Routes handle HTTP only, services handle business logic only, repositories handle data access only (grep for SQL in routes, verify no res.json() in services, ensure no business logic in repositories)

- [ ] **Separated Concerns** — Validation, authorization, business logic, and data access are in separate modules/functions (verify security logic not mixed with business logic, test each concern independently, ensure clear boundaries)

- [ ] **Cross-Cutting Abstraction** — Logging, auth, error handling extracted to middleware/decorators/HOFs (grep for repeated try/catch or auth checks, verify abstractions are reusable, test concerns can be composed)

- [ ] **Dependency Injection** — Services receive dependencies via constructor, not imported globals (verify testable without database, ensure dependencies injectable, test with mock implementations)

- [ ] **Behavior Preservation** — All existing tests pass after refactoring, no changes to public API (run full test suite, verify each layer testable independently, ensure error handling equivalent)

---

**Key Takeaway**: Functions with a single responsibility are exponentially easier to test, understand, and secure; apply SRP by separating validation, business logic, and data access into distinct layers with clear boundaries.
