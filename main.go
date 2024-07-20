package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// global token sign, not sure if safe
var JwtSecret = []byte("verySecret")

type Weapon struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Armor struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type JwtClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

func Hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, Warrior! Great to see you")
}

func GetWeapon(c echo.Context) error {
	WeaponName := c.QueryParam("name")
	WeaponType := c.QueryParam("type")

	dataType := c.Param("data")
	if dataType == "string" {
		return c.String(http.StatusOK, fmt.Sprintf("Your weapon name is %s\nand it's type is %s\n", WeaponName, WeaponType))
	}
	if dataType == "json" {
		return c.JSON(http.StatusOK, map[string]string{
			"name": WeaponName,
			"type": WeaponType,
		})
	}
	//Example http://localhost:8080/weapons/get/string?name=Flamberge&type=two-handed
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": "you need to let us know if you want string or json data",
	})
}

// not using Echo
func AddWeapon(c echo.Context) error {
	weapon := Weapon{}

	defer c.Request().Body.Close()
	b, err := io.ReadAll(c.Request().Body) //b = body

	if err != nil {
		log.Printf("Failed to read request Body of AddWeapon: %s", err)
		return c.String(http.StatusInternalServerError, "")
	}

	err = json.Unmarshal(b, &weapon)
	if err != nil {
		log.Printf("Failed unmarshaling in AddWeapon: %s", err)
		return c.String(http.StatusInternalServerError, "")
	}
	log.Printf("%s added to armory!", weapon.Name)
	return c.String(http.StatusOK, "More weapons to use!")
}

// Using Echo
func AddArmor(c echo.Context) error {
	armor := Armor{}

	err := c.Bind(&armor)
	if err != nil {
		log.Printf("Failed processing AddArmor request: %s", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	log.Printf("%s added to armory!", armor.Name)
	return c.String(http.StatusOK, "More armor to use!")
}

func MainAdmin(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome, Quartermaster!")
}

func MainCookie(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome, Warrior!")
}

func MainJwt(c echo.Context) error {
	//accesing claims
	user := c.Get("user") //echo's default key name is 'user'
	token := user.(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	log.Println("Username:", claims["name"], "User ID:", claims["jti"])

	return c.String(http.StatusOK, "This is top secret jwt page!")
}

//	func CheckCredential(username, password string, c echo.Context) bool{
//		//checking DB
//		if username == "Fergus" && password == "fergus123"{
//			return true
//		}
//		return false
//	}

func Login(c echo.Context) error {
	username := c.QueryParam("username")
	password := c.QueryParam("password")

	//Check DB
	if username == "eka" && password == "eka123" {
		// or use cookie := new(http.Cookie)
		cookie := &http.Cookie{}

		cookie.Name = "SessionID"
		cookie.Value = "some_string"
		cookie.Expires = time.Now().Add(48 * time.Hour)
		c.SetCookie(cookie)

		//Create JWT Token
		token, err := CreateJwtToken()
		if err != nil {
			log.Println(err)
			return c.String(http.StatusInternalServerError, "I wonder what went wrong")
		}

		//directly passing the token to jwt
		JwtCookie := &http.Cookie{}

		JwtCookie.Name = "JWTCookie"
		JwtCookie.Value = token
		JwtCookie.Expires = time.Now().Add(48 * time.Hour)
		c.SetCookie(JwtCookie)

		log.Println("JWT Token set in cookie:", JwtCookie.Value)

		// return c.String(http.StatusOK, "You're finally awake!")
		return c.JSON(http.StatusOK, map[string]string{
			"message": "You're finally awake!",
			"token":   token,
		})
	}
	return c.String(http.StatusOK, "Who are you?")
}

func CreateJwtToken() (string, error) {
	claims := JwtClaims{
		"eka",
		jwt.StandardClaims{
			Id:        "main_user_id",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token, err := rawToken.SignedString(JwtSecret)
	if err != nil {
		log.Println(err)
	}
	return token, nil
}

// ////////////// MIDDLEWARE ////////////////
func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, "Armory/1.0")
		c.Response().Header().Set("Region", "Bali")

		return next(c)
	}
}

func CheckCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// values should be from a cookie store
		cookie, err := c.Cookie("SessionID")
		// jika encounter error
		if err != nil {
			//jika mendapatkan error dengan string "named cookie not present"
			if strings.Contains(err.Error(), "named cookie not present") {
				return c.String(http.StatusUnauthorized, "You don't have any cookie T_T")
			}
			log.Println(err)
			return err
		}
		if cookie.Value == "some_string" {
			return next(c)
		}
		return c.String(http.StatusUnauthorized, "You don't have the right cookie")
	}
}

// //////////////////////////////////////////
func main() {
	fmt.Println("Hello, User! Great to see you")

	e := echo.New()
	e.Use(ServerHeader)

	//Groups
	AdminGroup := e.Group("/admin")
	CookieGroup := e.Group("/cookie")
	JwtGroup := e.Group("/jwt")

	//Admin
	AdminGroup.GET("/main", MainAdmin)
	AdminGroup.Use(middleware.Logger()) //logs the server interaction
	AdminGroup.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		//checking DB
		if username == "fergus" && password == "fergus123" {
			return true, nil
		}
		return false, nil
	}))

	//Cookie
	CookieGroup.Use(CheckCookie)
	CookieGroup.Use(middleware.Logger())
	CookieGroup.GET("/main", MainCookie)

	//JWT
	JwtGroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningMethod: "HS512",
		SigningKey:    JwtSecret, //
		TokenLookup:   "cookie:JWTCookie",
	}))
	JwtGroup.GET("/jwt", MainJwt)

	e.GET("/login", Login)
	e.GET("/", Hello)
	e.GET("/weapons/get/:data", GetWeapon)
	e.POST("/weapons/add/", AddWeapon)
	e.POST("/armors/add/", AddArmor)

	e.Start(":8080")
}
