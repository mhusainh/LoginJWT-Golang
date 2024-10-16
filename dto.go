// dto.go
package main

// CreateTodoDTO for creating a new todo
type CreateTodoDTO struct {
    Title string `json:"title" binding:"required"`
}

// UpdateTodoDTO for updating an existing todo
type UpdateTodoDTO struct {
    Title     string `json:"title"`
    Completed bool   `json:"completed"`
}

// LoginDTO for user authentication
type LoginDTO struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

// CreateUserDTO for creating a new user
type CreateUserDTO struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
    Role     string `json:"role" binding:"required"` // Should be "Editor" or "Admin"
}
