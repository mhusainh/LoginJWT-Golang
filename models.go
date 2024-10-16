// models.go
package main

// User represents a user in the system
type User struct {
    ID           int    `json:"id"`
    Username     string `json:"username"`
    PasswordHash string `json:"-"`
    Role         string `json:"role"`
}

// Todo represents a todo item
type Todo struct {
    ID        int    `json:"id"`
    Title     string `json:"title"`
    Completed bool   `json:"completed"`
    UserID    int    `json:"user_id"`
}
