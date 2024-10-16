// routes.go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)

// Route registers all available routes
func Route(e *echo.Echo) {
    // Public routes
    e.POST("/login", Login)

    // Group for authenticated routes
    auth := e.Group("")
    auth.Use(middleware.JWTWithConfig(middleware.JWTConfig{
        SigningKey: jwtSecret,
    }))

    // Routes for Editors (and Admins)
    editor := auth.Group("/todos")
    editor.Use(RoleMiddleware("Editor"))
    editor.GET("", Todos)
    editor.POST("", CreateTodo)
    editor.PUT("/:id", UpdateTodo)
    editor.DELETE("/:id", DeleteTodo)

    // Routes for Admins
    admin := auth.Group("/users")
    admin.Use(RoleMiddleware("Admin"))
    admin.GET("", GetUsers)
    admin.POST("", CreateUser)
    admin.PUT("/:id", UpdateUser)
    admin.DELETE("/:id", DeleteUser)
}
