## Create table file up and down using migration

```go
  migrate create --ext sql -dir database/migrations create_table_users
```

## Running migration up

```go
  migrate -database "postgres://postgres:postgres@localhost:5432/employees?sslmode=disable" -path db/migrations up
```

## Running migration down

```go
  migrate -database "postgres://postgres:postgres@localhost:5432/employees?sslmode=disable" -path db/migrations down
```

## Dirty state

**Check version**

```go
  migrate -database "postgres://postgres:postgres@localhost:5432/employees?sslmode=disable" -path db/migrations version
```

**Force rollback**

```go
  migrate -database "postgres://postgres:postgres@localhost:5432/employees?sslmode=disable" -path db/migrations force 20240703040827
```
