// @title Backpack API
// @version 1.0
// @description This is a sample server for managing todos with Auth0 authentication.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:3000
// @BasePath /

// @securityDefinitions.oauth2.auth0 Auth0
// @authorizationUrl https://{domain}/authorize
// @tokenUrl https://{domain}/oauth/token
// @scope.read Grants read access
// @scope.write Grants write access
package main

import (
	_ "Backpack/docs"
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/auth0-community/go-auth0"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	jose "gopkg.in/square/go-jose.v2"
)

type Response struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Todo struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Completed bool   `json:"completed"`
}

type User struct {
	ID       string `json:"id" bson:"_id,omitempty"`
	Username string `json:"username" bson:"username"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	audience string
	domain   string
	client   *mongo.Client
)

func main() {
	log.Println("Setting Auth0 variables")
	setAuth0Variables()
	log.Println("Initializing MongoDB")
	initMongoDB()

	r := gin.Default()

	authorized := r.Group("/")
	authorized.Use(authRequired())

	authorized.GET("/api/todos", func(c *gin.Context) {
		log.Println("GET /api/todos endpoint called")
		getTodos(c)
	})
	authorized.POST("/api/todos", func(c *gin.Context) {
		log.Println("POST /api/todos endpoint called")
		createTodo(c)
	})
	authorized.PUT("/api/todos/:id", func(c *gin.Context) {
		log.Printf("PUT /api/todos/%s endpoint called", c.Param("id"))
		updateTodo(c)
	})
	authorized.DELETE("/api/todos/:id", func(c *gin.Context) {
		log.Printf("DELETE /api/todos/%s endpoint called", c.Param("id"))
		deleteTodo(c)
	})
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.POST("/api/users", func(c *gin.Context) {
		log.Println("POST /api/users endpoint called")
		createUser(c)
	})
	r.GET("/api/users/:id", func(c *gin.Context) {
		log.Printf("GET /api/users/%s endpoint called", c.Param("id"))
		getUser(c)
	})
	r.POST("/api/login", func(c *gin.Context) {
		log.Println("POST /api/login endpoint called")
		login(c)
	})

	err := r.Run(":3000")
	if err != nil {
		log.Fatal(err)
	}
}

func setAuth0Variables() {
	audience = os.Getenv("AUTH0_API_IDENTIFIER")
	domain = os.Getenv("AUTH0_DOMAIN")

	log.Printf("Auth0 API Identifier: %s", audience)
	log.Printf("Auth0 Domain: %s", domain)
}

func initMongoDB() {
	var err error
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	log.Println("Connected to MongoDB!")
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("Starting authentication middleware")
		client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: "https://" + domain + "/.well-known/jwks.json"}, nil)
		config := auth0.NewConfiguration(client, []string{audience}, "https://"+domain+"/", jose.RS256)
		validator := auth0.NewValidator(config, nil)

		log.Println("Validating token")
		_, err := validator.ValidateRequest(c.Request)
		if err != nil {
			log.Println("Invalid token")
			resp := ErrorResponse{Error: "Invalid token"}
			c.JSON(http.StatusUnauthorized, resp)
			c.Abort()
			return
		}
		log.Println("Token validated successfully")
		c.Next()
	}
}

// @Summary Get all todos
// @Description Get details of all todos
// @Tags todos
// @Accept  json
// @Produce  json
// @Success 200 {object} Response
// @Failure 500 {object} ErrorResponse
// @Router /api/todos [get]
func getTodos(c *gin.Context) {
	collection := client.Database("your-database-name").Collection("todos")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		resp := ErrorResponse{Error: "Failed to retrieve todos"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	defer cursor.Close(ctx)

	var todos []Todo
	if err = cursor.All(ctx, &todos); err != nil {
		resp := ErrorResponse{Error: "Failed to parse todos"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	resp := Response{Message: "Todos retrieved successfully", Data: todos}
	c.JSON(http.StatusOK, resp)
}

// @Summary Create a new todo
// @Description Create a new todo item
// @Tags todos
// @Accept  json
// @Produce  json
// @Param todo body Todo true "Todo item"
// @Success 201 {object} Response
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/todos [post]
func createTodo(c *gin.Context) {
	var newTodo Todo
	if err := c.ShouldBindJSON(&newTodo); err != nil {
		resp := ErrorResponse{Error: "Invalid input"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	collection := client.Database("your-database-name").Collection("todos")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, newTodo)
	if err != nil {
		resp := ErrorResponse{Error: "Failed to create todo"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	newTodo.ID = result.InsertedID.(int) // Assuming the ID is an integer
	resp := Response{Message: "Todo created", Data: newTodo}
	c.JSON(http.StatusCreated, resp)
}

// updateTodo updates an existing todo item.
// @Summary Update a todo item
// @Description Update the details of an existing todo item by its ID
// @Tags todos
// @Accept json
// @Produce json
// @Param id path int true "Todo ID"
// @Param todo body Todo true "Todo item"
// @Success 200 {object} Response
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/todos/{id} [put]
func updateTodo(c *gin.Context) {
	var updatedTodo Todo
	if err := c.ShouldBindJSON(&updatedTodo); err != nil {
		resp := ErrorResponse{Error: "Invalid input"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	id := c.Param("id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		resp := ErrorResponse{Error: "Invalid ID"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	collection := client.Database("your-database-name").Collection("todos")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"id": idInt}
	update := bson.M{"$set": updatedTodo}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		resp := ErrorResponse{Error: "Failed to update todo"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	if result.MatchedCount == 0 {
		resp := ErrorResponse{Error: "Todo not found"}
		c.JSON(http.StatusNotFound, resp)
		return
	}

	resp := Response{Message: "Todo updated", Data: updatedTodo}
	c.JSON(http.StatusOK, resp)
}

// deleteTodo deletes a todo item based on the provided ID.
//
// @Summary Delete a todo item
// @Description Delete a todo item by ID
// @Tags todos
// @Accept json
// @Produce json
// @Param id path int true "Todo ID"
// @Success 200 {object} Response
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/todos/{id} [delete]
func deleteTodo(c *gin.Context) {
	id := c.Param("id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		resp := ErrorResponse{Error: "Invalid ID"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	collection := client.Database("your-database-name").Collection("todos")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"id": idInt}
	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		resp := ErrorResponse{Error: "Failed to delete todo"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	if result.DeletedCount == 0 {
		resp := ErrorResponse{Error: "Todo not found"}
		c.JSON(http.StatusNotFound, resp)
		return
	}

	resp := Response{Message: "Todo deleted"}
	c.JSON(http.StatusOK, resp)
}

// createUser creates a new user in the database.
// @Summary Create a new user
// @Description Create a new user with the provided JSON payload
// @Tags users
// @Accept  json
// @Produce  json
// @Param user body User true "User data"
// @Success 201 {object} Response "User created"
// @Failure 400 {object} ErrorResponse "Invalid input"
// @Failure 500 {object} ErrorResponse "Failed to create user"
// @Router /api/users [post]
func createUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		resp := ErrorResponse{Error: "Invalid input"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	collection := client.Database("your-database-name").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		resp := ErrorResponse{Error: "Failed to create user"}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	resp := Response{Message: "User created", Data: result.InsertedID}
	c.JSON(http.StatusCreated, resp)
}

// @Summary Get user by ID
// @Description Retrieve a user by their ID from the database
// @Tags users
// @Accept  json
// @Produce  json
// @Param id path string true "User ID"
// @Success 200 {object} Response
// @Failure 404 {object} ErrorResponse
// @Router /api/users/{id} [get]
func getUser(c *gin.Context) {
	id := c.Param("id")

	collection := client.Database("your-database-name").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		resp := ErrorResponse{Error: "User not found"}
		c.JSON(http.StatusNotFound, resp)
		return
	}

	resp := Response{Message: "User retrieved", Data: user}
	c.JSON(http.StatusOK, resp)
}

// login authenticates a user.
// @Summary Login a user
// @Description Authenticate a user with the provided JSON payload
// @Tags users
// @Accept  json
// @Produce  json
// @Param credentials body Credentials true "User credentials"
// @Success 200 {object} Response "Login successful"
// @Failure 400 {object} ErrorResponse "Invalid input"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Router /api/login [post]
func login(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		resp := ErrorResponse{Error: "Invalid input"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	collection := client.Database("your-database-name").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, bson.M{"username": creds.Username, "password": creds.Password}).Decode(&user)
	if err != nil {
		resp := ErrorResponse{Error: "Unauthorized"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	resp := Response{Message: "Login successful"}
	c.JSON(http.StatusOK, resp)
}
