package app

import (
	"github.com/muchlist/KalselDevApi/dao"
	"github.com/muchlist/KalselDevApi/handler"
	"github.com/muchlist/KalselDevApi/service"
	"github.com/muchlist/KalselDevApi/utils/crypt"
	"github.com/muchlist/KalselDevApi/utils/mjwt"
)

var (
	//Utils
	cryptoUtils = crypt.NewCrypto()
	jwt         = mjwt.NewJwt()

	//Dao
	userDao = dao.NewUserDao()

	//Service
	userService = service.NewUserService(userDao, cryptoUtils, jwt)

	//Controller or Handler
	pingHandler = handler.NewPingHandler()
	userHandler = handler.NewUserHandler(userService)
)
