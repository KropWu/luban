/*
Copyright 2021 The DnsJia Authors.
WebSite:  https://github.com/dnsjia/luban
Email:    OpenSource@dnsjia.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"github.com/dnsjia/luban/common"
	"github.com/dnsjia/luban/controller/response"
	"github.com/dnsjia/luban/models"
	"github.com/dnsjia/luban/services"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// 用户注册
func Register(c *gin.Context) {
	var user models.User
	err := CheckParams(c, &user)
	if err != nil {
		return
	}
	// 创建用户的时候加密用户的密码
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashPassword)
	u, err := services.UserRegister(user)
	if err != nil {
		common.LOG.Error(fmt.Sprintf("用户：%v, 注册失败", user.UserName), zap.Any("err", err))
		response.FailWithMessage(response.UserRegisterFail, err.Error(), c)
	} else {
		response.ResultOk(0, u, "注册成功", c)
	}
}

// 用户登录
func Login(c *gin.Context) {
	var user models.LoginUser
	err := CheckParams(c, &user)
	if err != nil {
		return
	}
	if user.Email == "" {
		response.FailWithMessage(response.UserNameEmpty, "", c)
		return
	}
	if user.Password == "" {
		response.FailWithMessage(response.UserPassEmpty, "", c)
		return
	}
	// 判断前端是否以LDAP方式登录
	if user.Ldap {
		// 从数据库查询用户是否存在
		u, err1 := services.PassLogin(user.Email, user.Password)
		if err1 == nil {
			if !*u.Status {
				response.FailWithMessage(response.UserDisable, "", c)
				return
			}

			c.Set("username", u.UserName)
		}
		// 如果数据库中用户不存在，开始从ldap获取信息
		// password login fail, try ldap
		if common.Config.LDAP.Enable {
			//
			user, err2 := services.LdapLogin(user.Email, user.Password)
			if err2 == nil {
				if !*user.Status {
					response.FailWithMessage(response.UserDisable, "", c)
					return
				}
				c.Set("username", user.UserName)
				// 发放Token
				token, err := common.ReleaseToken(*user)
				if err != nil {
					common.LOG.Error(fmt.Sprintf("token generate err: %v", err))
					response.FailWithMessage(response.InternalServerError, fmt.Sprintf("token generate err：%v", err), c)
					return
				}
				response.OkWithDetailed(gin.H{"token": token, "username": u.UserName, "role": u.Role, "email": u.Email}, "登录成功", c)
				return
			}
			response.FailWithMessage(response.LDAPUserLoginFailed, "", c)
			return
		}
	}

	u, err := services.Login(user)
	if err != nil {
		common.LOG.Error("用户登录失败", zap.Any("err", err))
		response.FailWithMessage(response.InternalServerError, err.Error(), c)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(user.Password)); err != nil {
		// 密码错误
		response.FailWithMessage(response.AuthError, "", c)
		return
	}
	if !*u.Status {
		response.FailWithMessage(response.UserDisable, "", c)
		return
	}
	// 发放Token
	token, err := common.ReleaseToken(u)
	if err != nil {
		common.LOG.Error(fmt.Sprintf("token generate err: %v", err))
		response.FailWithMessage(response.InternalServerError, fmt.Sprintf("token generate err：%v", err), c)
		return
	}
	response.OkWithDetailed(gin.H{"token": token, "username": u.UserName, "role": u.Role, "email": u.Email}, "登录成功", c)
	return

}

// 获取所有用户列表
func UserList(c *gin.Context) {
	query := models.PaginationQ{}
	if c.ShouldBindQuery(&query) != nil {
		response.FailWithMessage(response.ParamError, response.ParamErrorMsg, c)
		return
	}
	var userList []models.User
	if err := services.ListUsers(&query, &userList); err != nil {
		common.LOG.Error("获取用户列表失败", zap.Any("err", err))
		response.FailWithMessage(response.InternalServerError, "获取用户列表失败", c)
	} else {
		response.OkWithDetailed(response.PageResult{
			Data:  userList,
			Total: query.Total,
			Size:  query.Size,
			Page:  query.Page,
		}, "获取用户列表成功", c)
	}
}

// 更新用户信息
func UpdateUserInfo(c *gin.Context) {
	var user models.UpdateUserInfo
	err := c.ShouldBindJSON(&user)
	if err != nil {
		response.FailWithMessage(response.ParamError, response.ParamErrorMsg, c)
		return
	}

	err = services.UpdateUserInfo(models.User{
		GModel: models.GModel{
			ID: user.ID,
		},
		UserName: user.UserName,
		Phone:    user.Phone,
		Email:    user.Email,
		NickName: user.NickName,
		Status:   user.Status,
		RoleId:   user.RoleId,
	})
	if err != nil {
		common.LOG.Error("更新失败", zap.Any("err", err))
		response.FailWithMessage(response.InternalServerError, "更新失败", c)
		return
	}
	response.OkWithMessage("更新成功", c)
}

// 根据ID删除用户
func DelUser(c *gin.Context) {
	var userIds models.UserId
	err := c.ShouldBindJSON(&userIds)
	if err != nil {
		response.FailWithMessage(response.ParamError, response.ParamErrorMsg, c)
		return
	}
	err = services.DelUser(userIds)
	if err != nil {
		common.LOG.Error("删除失败", zap.Any("err", err))
		response.FailWithMessage(response.InternalServerError, "删除失败", c)
		return
	}
	response.OkWithMessage("删除成功", c)
}

// 根据ID获取用户信息
func GetUserInfoById(c *gin.Context) {
	id := c.GetInt("userId")
	fmt.Println(id)
	data, err := services.GetUserInfoById(id)
	if err != nil {
		common.LOG.Error("搜索用户失败", zap.Any("err", err))
		response.FailWithMessage(response.InternalServerError, "搜索用户失败", c)
	} else {
		response.OkWithData(data, c)
	}
	return
}
