import {post, get, del} from "@/plugin/utils/request";

export const login = (params) => post('/api/v1/user/login', params)
export const userList = (params) => get('/api/v1/user/list', params)

