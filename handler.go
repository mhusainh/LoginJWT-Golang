// handler.go
package main

import (
    "database/sql"
    "fmt"
    "net/http"
    "strconv"
    "time"

    "github.com/golang-jwt/jwt"
    "github.com/labstack/echo/v4"
    "golang.org/x/crypto/bcrypt"
    "github.com/go-sql-driver/mysql"
)

var jwtSecret = []byte("your_secret_key") // Ganti dengan kunci rahasia Anda

// Login handles user authentication and returns a JWT token
func Login(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    var creds LoginDTO
    if err := c.Bind(&creds); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
    }

    // Fetch user from database
    var user User
    row := db.QueryRow("SELECT id, password_hash, role FROM users WHERE username = ?", creds.Username)
    err := row.Scan(&user.ID, &user.PasswordHash, &user.Role)
    if err != nil {
        fmt.Println("Error fetching user:", err)
        return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid username or password"})
    }

    // Compare passwords
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
        fmt.Println("Password mismatch:", err)
        return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid username or password"})
    }

    // Create JWT token
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["user_id"] = user.ID
    claims["username"] = creds.Username
    claims["role"] = user.Role
    claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

    t, err := token.SignedString(jwtSecret)
    if err != nil {
        fmt.Println("Error signing token:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"token": t})
}

// RoleMiddleware checks if the user has the required role
func RoleMiddleware(role string) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            userTokenInterface := c.Get("user")
            if userTokenInterface == nil {
                fmt.Println("No user token found in context")
                return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
            }
            userToken, ok := userTokenInterface.(*jwt.Token)
            if !ok {
                fmt.Println("User token in context is not of type *jwt.Token")
                return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
            }
            claims, ok := userToken.Claims.(jwt.MapClaims)
            if !ok {
                fmt.Println("Failed to assert token claims as jwt.MapClaims")
                return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token claims"})
            }
            userRole, ok := claims["role"].(string)
            if !ok {
                fmt.Println("Role not found or not a string in token claims")
                return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid role in token"})
            }
            if userRole != role && userRole != "Admin" {
                return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
            }
            return next(c)
        }
    }
}

// Todos retrieves todos for the authenticated user
func Todos(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    userToken := c.Get("user").(*jwt.Token)
    claims := userToken.Claims.(jwt.MapClaims)
    userID := int(claims["user_id"].(float64))

    rows, err := db.Query("SELECT id, title, completed, user_id FROM todos WHERE user_id = ?", userID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }
    defer rows.Close()

    var todos []Todo
    for rows.Next() {
        var todo Todo
        if err := rows.Scan(&todo.ID, &todo.Title, &todo.Completed, &todo.UserID); err != nil {
            return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
        }
        todos = append(todos, todo)
    }

    return c.JSON(http.StatusOK, todos)
}

// CreateTodo creates a new todo for the authenticated user
func CreateTodo(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    var dto CreateTodoDTO
    if err := c.Bind(&dto); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
    }

    userToken := c.Get("user").(*jwt.Token)
    claims := userToken.Claims.(jwt.MapClaims)
    userID := int(claims["user_id"].(float64))

    _, err := db.Exec("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)",
        dto.Title, false, userID)
    if err != nil {
        fmt.Println("Error inserting todo:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "Todo created successfully"})
}

// UpdateTodo updates an existing todo for the authenticated user
func UpdateTodo(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    id, err := strconv.Atoi(c.Param("id"))
    if err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
    }

    userToken := c.Get("user").(*jwt.Token)
    claims := userToken.Claims.(jwt.MapClaims)
    userID := int(claims["user_id"].(float64))

    // Verify ownership
    var ownerID int
    err = db.QueryRow("SELECT user_id FROM todos WHERE id = ?", id).Scan(&ownerID)
    if err != nil {
        fmt.Println("Error fetching todo owner:", err)
        return c.JSON(http.StatusNotFound, echo.Map{"error": "Todo not found"})
    }
    if ownerID != userID {
        return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
    }

    var dto UpdateTodoDTO
    if err := c.Bind(&dto); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
    }

    _, err = db.Exec("UPDATE todos SET title = ?, completed = ? WHERE id = ?",
        dto.Title, dto.Completed, id)
    if err != nil {
        fmt.Println("Error updating todo:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "Todo updated successfully"})
}

// DeleteTodo deletes a todo for the authenticated user
func DeleteTodo(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    id, err := strconv.Atoi(c.Param("id"))
    if err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
    }

    userToken := c.Get("user").(*jwt.Token)
    claims := userToken.Claims.(jwt.MapClaims)
    userID := int(claims["user_id"].(float64))

    // Verify ownership
    var ownerID int
    err = db.QueryRow("SELECT user_id FROM todos WHERE id = ?", id).Scan(&ownerID)
    if err != nil {
        fmt.Println("Error fetching todo owner:", err)
        return c.JSON(http.StatusNotFound, echo.Map{"error": "Todo not found"})
    }
    if ownerID != userID {
        return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
    }

    _, err = db.Exec("DELETE FROM todos WHERE id = ?", id)
    if err != nil {
        fmt.Println("Error deleting todo:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "Todo deleted successfully"})
}

// GetUsers retrieves all users (Admin only)
func GetUsers(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    rows, err := db.Query("SELECT id, username, role FROM users")
    if err != nil {
        fmt.Println("Error fetching users:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        if err := rows.Scan(&user.ID, &user.Username, &user.Role); err != nil {
            fmt.Println("Error scanning user:", err)
            return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
        }
        users = append(users, user)
    }

    return c.JSON(http.StatusOK, users)
}

// CreateUser creates a new user (Admin only)
func CreateUser(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    var dto CreateUserDTO
    if err := c.Bind(&dto); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
    }

    // Validate role
    if dto.Role != "Editor" && dto.Role != "Admin" {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid role"})
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println("Error hashing password:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    _, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        dto.Username, string(hashedPassword), dto.Role)
    if err != nil {
        fmt.Println("Error inserting user:", err)
        if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
            return c.JSON(http.StatusBadRequest, echo.Map{"error": "Username already exists"})
        }
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "User created successfully"})
}

// UpdateUser updates an existing user (Admin only)
func UpdateUser(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    id, err := strconv.Atoi(c.Param("id"))
    if err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
    }

    var dto CreateUserDTO
    if err := c.Bind(&dto); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
    }

    // Validate role
    if dto.Role != "Editor" && dto.Role != "Admin" {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid role"})
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println("Error hashing password:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    _, err = db.Exec("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
        dto.Username, string(hashedPassword), dto.Role, id)
    if err != nil {
        fmt.Println("Error updating user:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "User updated successfully"})
}

// DeleteUser deletes a user (Admin only)
func DeleteUser(c echo.Context) error {
    db := c.Get("db").(*sql.DB)
    id, err := strconv.Atoi(c.Param("id"))
    if err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
    }

    _, err = db.Exec("DELETE FROM users WHERE id = ?", id)
    if err != nil {
        fmt.Println("Error deleting user:", err)
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
    }

    return c.JSON(http.StatusOK, echo.Map{"message": "User deleted successfully"})
}
