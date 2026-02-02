# Error Handling in the Go SDK

## Design Philosophy

The AxonFlow Go SDK follows idiomatic Go error handling patterns rather than implementing a hierarchy of custom exception types. This is an intentional design decision aligned with Go best practices.

## Why No Custom Exception Hierarchy?

### Go's Error Philosophy

Go's approach to error handling differs fundamentally from languages like Python, Java, and TypeScript:

1. **Errors are values** - In Go, errors are just values that implement the `error` interface
2. **No exceptions** - Go doesn't have try/catch; errors are returned explicitly
3. **Simplicity** - The community prefers simple, explicit error handling over complex hierarchies

### Comparison with Other SDKs

| SDK | Approach | Rationale |
|-----|----------|-----------|
| **Go** | `error` interface | Idiomatic Go pattern |
| Python | `AxonFlowError` hierarchy | Pythonic exception handling |
| Java | `AxonFlowException` hierarchy | Java checked exceptions pattern |
| TypeScript | `AxonFlowError` hierarchy | JavaScript/TypeScript conventions |

## Error Handling Patterns

### Basic Pattern

```go
client, err := axonflow.NewClient(axonflow.Config{
    Endpoint: "http://localhost:8080",
})
if err != nil {
    log.Fatalf("failed to create client: %v", err)
}

result, err := client.HealthCheck(ctx)
if err != nil {
    log.Printf("health check failed: %v", err)
    return err
}
```

### Checking Error Types

Use `errors.Is()` and `errors.As()` for type checking:

```go
import "errors"

result, err := client.ProxyLLMCall(ctx, request)
if err != nil {
    // Check for specific error conditions
    var apiErr *axonflow.APIError
    if errors.As(err, &apiErr) {
        log.Printf("API error: status=%d, message=%s", apiErr.StatusCode, apiErr.Message)
        return
    }

    // Check for timeout
    if errors.Is(err, context.DeadlineExceeded) {
        log.Printf("request timed out")
        return
    }

    // Generic error handling
    log.Printf("unexpected error: %v", err)
}
```

### Error Types Provided

The Go SDK provides these error types when appropriate:

```go
// APIError represents an error response from the AxonFlow API
type APIError struct {
    StatusCode int
    Message    string
    RequestID  string
}

func (e *APIError) Error() string {
    return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}
```

### Wrapping Errors

When propagating errors, wrap them with context:

```go
result, err := client.GeneratePlan(ctx, request)
if err != nil {
    return fmt.Errorf("failed to generate plan for task %s: %w", taskID, err)
}
```

## Best Practices

### 1. Always Check Errors

```go
// Good
result, err := client.HealthCheck(ctx)
if err != nil {
    return err
}

// Bad - ignoring errors
result, _ := client.HealthCheck(ctx)
```

### 2. Add Context When Propagating

```go
// Good - adds context
if err != nil {
    return fmt.Errorf("processing user %s: %w", userID, err)
}

// Less helpful - loses context
if err != nil {
    return err
}
```

### 3. Use Sentinel Errors for Known Conditions

```go
import "errors"

var (
    ErrNotFound      = errors.New("resource not found")
    ErrUnauthorized  = errors.New("unauthorized")
    ErrRateLimited   = errors.New("rate limited")
)

// Check with errors.Is()
if errors.Is(err, ErrNotFound) {
    // Handle not found
}
```

### 4. Handle Errors at the Right Level

```go
// Handle at the appropriate abstraction level
func processRequest(ctx context.Context, client *axonflow.Client) error {
    result, err := client.ProxyLLMCall(ctx, req)
    if err != nil {
        // Log here if this is the top-level handler
        // Or return wrapped error if caller should handle it
        return fmt.Errorf("execute query: %w", err)
    }
    return nil
}
```

## HTTP Status Code Mapping

The SDK maps HTTP status codes to appropriate error handling:

| Status Code | Handling |
|-------------|----------|
| 400 | Returns error with validation details |
| 401 | Returns error indicating authentication failure |
| 403 | Returns error indicating authorization failure |
| 404 | Returns error indicating resource not found |
| 429 | Returns error with rate limit information |
| 500+ | Returns error indicating server-side issue |

## Context and Cancellation

Always pass context for cancellation and timeout support:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

result, err := client.ProxyLLMCall(ctx, request)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Printf("request timed out after 30s")
    }
    return err
}
```

## References

- [Go Blog: Error handling and Go](https://go.dev/blog/error-handling-and-go)
- [Go Blog: Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors)
- [Effective Go: Errors](https://go.dev/doc/effective_go#errors)
