## **Prerequisites**

- Git
- JDK 25

## **Code Style**

### **Indentation**

Use 4 spaces.

### **Bracket style**

Use Allman bracket style for almost everything: classes, methods, large arrays, etc.

```java
class Foo
{
    // ...
}
```

Use this bracket style for empty annotations and records:

```java
public @interface FooBar {}
```

```java
public record FooBar(int x) {}
```

### **Naming convention**
Use `camelCase` for methods and variables:

```java
int fooBar = 21;
```

Use `PascalCase` for classes, annotations, etc:

```java
class FooBar
{
}
```

### **Format Command**

Use this command to automatically format code:

```bash
./gradlew spotlessApply
```

## **Documenting**

Use Markdown Javadoc.

## **Commiting**

### **Branches**

Use descriptive branch names and `kebab-case`:

```
feature/random-number-generator
```

### **Commit prefixes**

- `fix:`      for bug fixes.
- `tests:`    for unit tests.
- `docs:`     changes related to Javadoc.
- `feat:`     new feature || algorithm.
- `refactor:` code changes that don't add any new features.
- `examples:` code examples.

```
feat: add Argon2
```

### **Pull Requests**

Use pull request templates. links:

- [Open a Bug Fix PR](https://github.com/BorschtOverflow/CoffeeCrypt/compare/master...branch?template=bug-fix.md)
- [Open a Feature PR](https://github.com/BorschtOverflow/CoffeeCrypt/compare/master...branch?template=feature-request.md)

Thank you for contributing! 🎉
