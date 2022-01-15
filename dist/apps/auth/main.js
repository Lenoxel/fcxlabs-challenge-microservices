/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/auth/src/auth.controller.ts":
/*!******************************************!*\
  !*** ./apps/auth/src/auth.controller.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const loginUser_dto_1 = __webpack_require__(/*! apps/user/src/dto/loginUser.dto */ "./apps/user/src/dto/loginUser.dto.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/auth/src/auth.service.ts");
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    async login(loginUserDto) {
        return await this.authService.login(loginUserDto);
    }
};
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_a = typeof loginUser_dto_1.LoginUserDto !== "undefined" && loginUser_dto_1.LoginUserDto) === "function" ? _a : Object]),
    __metadata("design:returntype", typeof (_b = typeof Promise !== "undefined" && Promise) === "function" ? _b : Object)
], AuthController.prototype, "login", null);
AuthController = __decorate([
    (0, common_1.Controller)('api/v1/auth'),
    __metadata("design:paramtypes", [typeof (_c = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _c : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./apps/auth/src/auth.module.ts":
/*!**************************************!*\
  !*** ./apps/auth/src/auth.module.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const user_module_1 = __webpack_require__(/*! apps/user/src/user.module */ "./apps/user/src/user.module.ts");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./apps/auth/src/auth.controller.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/auth/src/auth.service.ts");
const jwt_strategy_1 = __webpack_require__(/*! ./jwt/jwt.strategy */ "./apps/auth/src/jwt/jwt.strategy.ts");
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true }),
            passport_1.PassportModule,
            jwt_1.JwtModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: async () => ({
                    secret: process.env.JWT_SECRET,
                }),
                inject: [config_1.ConfigService],
            }),
            (0, common_1.forwardRef)(() => user_module_1.UserModule),
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, jwt_strategy_1.JwtStrategy],
        exports: [auth_service_1.AuthService, jwt_strategy_1.JwtStrategy],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./apps/auth/src/auth.service.ts":
/*!***************************************!*\
  !*** ./apps/auth/src/auth.service.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const user_status_enum_1 = __webpack_require__(/*! apps/user/src/enums/user-status.enum */ "./apps/user/src/enums/user-status.enum.ts");
const user_service_1 = __webpack_require__(/*! apps/user/src/user.service */ "./apps/user/src/user.service.ts");
let AuthService = class AuthService {
    constructor(userService, jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }
    async login(loginUserDto) {
        const user = await this.validateUser(loginUserDto);
        const payload = {
            userId: user.id,
        };
        return {
            accessToken: this.jwtService.sign(payload),
        };
    }
    async validateUser(loginUserDto) {
        const { login, password } = loginUserDto;
        const user = await this.userService.findByLogin(login);
        if (!user) {
            throw new common_1.NotFoundException('Usuário não encontrado');
        }
        if (user.status !== user_status_enum_1.UserStatus.Active) {
            throw new common_1.UnauthorizedException(`Esse usuário está com o status ${user.status.valueOf()}`);
        }
        const validatePassword = await user.validatePassword(password);
        if (!validatePassword) {
            throw new common_1.UnauthorizedException('Login ou senha incorretos');
        }
        return user;
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof user_service_1.UserService !== "undefined" && user_service_1.UserService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./apps/auth/src/jwt/jwt-auth.guard.ts":
/*!*********************************************!*\
  !*** ./apps/auth/src/jwt/jwt-auth.guard.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtAuthGuard = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
};
JwtAuthGuard = __decorate([
    (0, common_1.Injectable)()
], JwtAuthGuard);
exports.JwtAuthGuard = JwtAuthGuard;


/***/ }),

/***/ "./apps/auth/src/jwt/jwt.strategy.ts":
/*!*******************************************!*\
  !*** ./apps/auth/src/jwt/jwt.strategy.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor() {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET,
        });
    }
    async validate(payload) {
        return {
            userId: payload.userId,
        };
    }
};
JwtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], JwtStrategy);
exports.JwtStrategy = JwtStrategy;


/***/ }),

/***/ "./apps/user/src/dto/createUser.dto.ts":
/*!*********************************************!*\
  !*** ./apps/user/src/dto/createUser.dto.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateUserDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const user_status_enum_1 = __webpack_require__(/*! ../enums/user-status.enum */ "./apps/user/src/enums/user-status.enum.ts");
class CreateUserDto {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "login", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "password", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsPhoneNumber)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "phoneNumber", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "cpf", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "birthDate", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "motherName", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(user_status_enum_1.UserStatus),
    __metadata("design:type", typeof (_a = typeof user_status_enum_1.UserStatus !== "undefined" && user_status_enum_1.UserStatus) === "function" ? _a : Object)
], CreateUserDto.prototype, "status", void 0);
exports.CreateUserDto = CreateUserDto;


/***/ }),

/***/ "./apps/user/src/dto/loginUser.dto.ts":
/*!********************************************!*\
  !*** ./apps/user/src/dto/loginUser.dto.ts ***!
  \********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginUserDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class LoginUserDto {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginUserDto.prototype, "login", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginUserDto.prototype, "password", void 0);
exports.LoginUserDto = LoginUserDto;


/***/ }),

/***/ "./apps/user/src/dto/recoverPassword.dto.ts":
/*!**************************************************!*\
  !*** ./apps/user/src/dto/recoverPassword.dto.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RecoverPasswordDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class RecoverPasswordDto {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RecoverPasswordDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], RecoverPasswordDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RecoverPasswordDto.prototype, "cpf", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RecoverPasswordDto.prototype, "newPassword", void 0);
exports.RecoverPasswordDto = RecoverPasswordDto;


/***/ }),

/***/ "./apps/user/src/dto/updateUser.dto.ts":
/*!*********************************************!*\
  !*** ./apps/user/src/dto/updateUser.dto.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserDto = void 0;
const createUser_dto_1 = __webpack_require__(/*! ./createUser.dto */ "./apps/user/src/dto/createUser.dto.ts");
class UpdateUserDto extends createUser_dto_1.CreateUserDto {
}
exports.UpdateUserDto = UpdateUserDto;


/***/ }),

/***/ "./apps/user/src/elastic-search/elastic-search.module.ts":
/*!***************************************************************!*\
  !*** ./apps/user/src/elastic-search/elastic-search.module.ts ***!
  \***************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ElasticSearchModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const elastic_search_service_1 = __webpack_require__(/*! ./elastic-search.service */ "./apps/user/src/elastic-search/elastic-search.service.ts");
const elasticsearch_1 = __webpack_require__(/*! @nestjs/elasticsearch */ "@nestjs/elasticsearch");
let ElasticSearchModule = class ElasticSearchModule {
};
ElasticSearchModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule,
            elasticsearch_1.ElasticsearchModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: async (configService) => ({
                    node: configService.get('ELASTICSEARCH_NODE'),
                    auth: {
                        username: configService.get('ELASTICSEARCH_USERNAME'),
                        password: configService.get('ELASTICSEARCH_PASSWORD'),
                    },
                }),
                inject: [config_1.ConfigService],
            }),
        ],
        providers: [elastic_search_service_1.ElasticSearchService],
        exports: [elastic_search_service_1.ElasticSearchService],
    })
], ElasticSearchModule);
exports.ElasticSearchModule = ElasticSearchModule;


/***/ }),

/***/ "./apps/user/src/elastic-search/elastic-search.service.ts":
/*!****************************************************************!*\
  !*** ./apps/user/src/elastic-search/elastic-search.service.ts ***!
  \****************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ElasticSearchService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const elasticsearch_1 = __webpack_require__(/*! @nestjs/elasticsearch */ "@nestjs/elasticsearch");
let ElasticSearchService = class ElasticSearchService {
    constructor(elasticsearchService) {
        this.elasticsearchService = elasticsearchService;
    }
    async search(text, fields) {
        const { body } = await this.elasticsearchService.search({
            index: 'users',
            body: {
                query: {
                    multi_match: {
                        query: text,
                        fields,
                    },
                },
            },
        });
        const hits = body.hits.hits;
        return hits.map((item) => item._source);
    }
    async index({ id, name, login, cpf, status, birthDate }) {
        return await this.elasticsearchService.index({
            index: 'users',
            body: {
                id,
                name,
                login,
                cpf,
                status,
                birthDate,
            },
        });
    }
    async update(user) {
        await this.remove(user.id);
        await this.index(user);
    }
    async remove(userId) {
        this.elasticsearchService.deleteByQuery({
            index: 'users',
            body: {
                query: {
                    match: {
                        id: userId,
                    },
                },
            },
        });
    }
};
ElasticSearchService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof elasticsearch_1.ElasticsearchService !== "undefined" && elasticsearch_1.ElasticsearchService) === "function" ? _a : Object])
], ElasticSearchService);
exports.ElasticSearchService = ElasticSearchService;


/***/ }),

/***/ "./apps/user/src/elastic-search/interfaces/userSearchBody.type.ts":
/*!************************************************************************!*\
  !*** ./apps/user/src/elastic-search/interfaces/userSearchBody.type.ts ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./apps/user/src/entities/user.entity.ts":
/*!***********************************************!*\
  !*** ./apps/user/src/entities/user.entity.ts ***!
  \***********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const bcrypt = __importStar(__webpack_require__(/*! bcrypt */ "bcrypt"));
const user_status_enum_1 = __webpack_require__(/*! ../enums/user-status.enum */ "./apps/user/src/enums/user-status.enum.ts");
let User = class User {
    async hashPassword() {
        this.password = await bcrypt.hash(this.password, 12);
    }
    async validatePassword(password) {
        return bcrypt.compare(password, this.password);
    }
};
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], User.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)('varchar'),
    __metadata("design:type", String)
], User.prototype, "name", void 0);
__decorate([
    (0, typeorm_1.Column)('varchar'),
    __metadata("design:type", String)
], User.prototype, "login", void 0);
__decorate([
    (0, typeorm_1.Column)('varchar'),
    __metadata("design:type", String)
], User.prototype, "password", void 0);
__decorate([
    (0, typeorm_1.Column)({ unique: true, type: 'varchar' }),
    __metadata("design:type", String)
], User.prototype, "email", void 0);
__decorate([
    (0, typeorm_1.Column)('varchar'),
    __metadata("design:type", String)
], User.prototype, "phoneNumber", void 0);
__decorate([
    (0, typeorm_1.Column)({ unique: true, type: 'varchar' }),
    __metadata("design:type", String)
], User.prototype, "cpf", void 0);
__decorate([
    (0, typeorm_1.Column)('date'),
    __metadata("design:type", String)
], User.prototype, "birthDate", void 0);
__decorate([
    (0, typeorm_1.Column)('varchar'),
    __metadata("design:type", String)
], User.prototype, "motherName", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: user_status_enum_1.UserStatus }),
    __metadata("design:type", typeof (_a = typeof user_status_enum_1.UserStatus !== "undefined" && user_status_enum_1.UserStatus) === "function" ? _a : Object)
], User.prototype, "status", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' }),
    __metadata("design:type", String)
], User.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ type: 'timestamp' }),
    __metadata("design:type", String)
], User.prototype, "updatedAt", void 0);
__decorate([
    (0, typeorm_1.BeforeInsert)(),
    (0, typeorm_1.BeforeUpdate)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], User.prototype, "hashPassword", null);
User = __decorate([
    (0, typeorm_1.Entity)()
], User);
exports.User = User;


/***/ }),

/***/ "./apps/user/src/enums/user-status.enum.ts":
/*!*************************************************!*\
  !*** ./apps/user/src/enums/user-status.enum.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserStatus = void 0;
var UserStatus;
(function (UserStatus) {
    UserStatus["Active"] = "Ativo";
    UserStatus["Blocked"] = "Bloqueado";
    UserStatus["Inactive"] = "Inativo";
})(UserStatus = exports.UserStatus || (exports.UserStatus = {}));


/***/ }),

/***/ "./apps/user/src/repositories/user.repository.ts":
/*!*******************************************************!*\
  !*** ./apps/user/src/repositories/user.repository.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserRepository = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const user_entity_1 = __webpack_require__(/*! ../entities/user.entity */ "./apps/user/src/entities/user.entity.ts");
const user_status_enum_1 = __webpack_require__(/*! ../enums/user-status.enum */ "./apps/user/src/enums/user-status.enum.ts");
let UserRepository = class UserRepository extends typeorm_1.Repository {
    async findByFilters(userSearchBody) {
        if (userSearchBody) {
            const { name, login, cpf, status, ageRange, birthDate, createdAt, updatedAt, } = userSearchBody;
            const queryBuilder = this.createQueryBuilder('user');
            let firstWhere = true;
            if (name) {
                if (firstWhere) {
                    queryBuilder.where('user.name = :name', { name });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.name = :name', { name });
                }
            }
            if (login) {
                if (firstWhere) {
                    queryBuilder.where('user.login = :login', { login });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.login = :login', { login });
                }
            }
            if (cpf) {
                if (firstWhere) {
                    queryBuilder.where('user.cpf = :cpf', { cpf });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.cpf = :cpf', { cpf });
                }
            }
            if (status) {
                if (firstWhere) {
                    queryBuilder.where('user.status = :status', { status });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.status = :status', { status });
                }
            }
            else {
                queryBuilder.andWhere('user.status = :status', {
                    status: user_status_enum_1.UserStatus.Active,
                });
            }
            return await queryBuilder.getMany();
        }
        else {
            return this.createQueryBuilder('user')
                .where('user.status = :status', {
                status: user_status_enum_1.UserStatus.Active,
            })
                .getMany();
        }
    }
    async userAlreadyExist(cpf, email, login) {
        return this.createQueryBuilder('user')
            .where('user.cpf = :cpf', { cpf })
            .orWhere('user.email = :email', { email })
            .orWhere('user.login = :login', { login })
            .getMany();
    }
    async createAndSave({ name, login, password, email, phoneNumber, cpf, birthDate, motherName, status, }) {
        const user = this.create();
        user.name = name;
        user.login = login;
        user.password = password;
        user.email = email;
        user.phoneNumber = phoneNumber;
        user.cpf = cpf;
        user.birthDate = birthDate;
        user.motherName = motherName;
        user.status = status;
        await this.insert(user);
    }
    async updateAndSave(user, { name, login, password, email, phoneNumber, cpf, birthDate, motherName, status, }) {
        user.name = name || user.name;
        user.login = login || user.login;
        user.password = password || user.password;
        user.email = email || user.email;
        user.phoneNumber = phoneNumber || user.phoneNumber;
        user.cpf = cpf || user.cpf;
        user.birthDate = birthDate || user.birthDate;
        user.motherName = motherName || user.motherName;
        user.status = status || user.status;
        await this.save(user);
    }
    async changePasswordAndSave(user, newPassword) {
        user.password = newPassword;
        await this.save(user);
    }
};
UserRepository = __decorate([
    (0, typeorm_1.EntityRepository)(user_entity_1.User)
], UserRepository);
exports.UserRepository = UserRepository;


/***/ }),

/***/ "./apps/user/src/user.controller.ts":
/*!******************************************!*\
  !*** ./apps/user/src/user.controller.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_auth_guard_1 = __webpack_require__(/*! apps/auth/src/jwt/jwt-auth.guard */ "./apps/auth/src/jwt/jwt-auth.guard.ts");
const createUser_dto_1 = __webpack_require__(/*! ./dto/createUser.dto */ "./apps/user/src/dto/createUser.dto.ts");
const recoverPassword_dto_1 = __webpack_require__(/*! ./dto/recoverPassword.dto */ "./apps/user/src/dto/recoverPassword.dto.ts");
const updateUser_dto_1 = __webpack_require__(/*! ./dto/updateUser.dto */ "./apps/user/src/dto/updateUser.dto.ts");
const userSearchBody_type_1 = __webpack_require__(/*! ./elastic-search/interfaces/userSearchBody.type */ "./apps/user/src/elastic-search/interfaces/userSearchBody.type.ts");
const user_service_1 = __webpack_require__(/*! ./user.service */ "./apps/user/src/user.service.ts");
let UserController = class UserController {
    constructor(userService) {
        this.userService = userService;
    }
    async getUsers() {
        return await this.userService.getUsers();
    }
    async getUsersByFilters(userSearchBody) {
        return await this.userService.getUsers(userSearchBody);
    }
    async getUserById(id) {
        return await this.userService.getUserById(id);
    }
    async createUser(createUserDto) {
        return await this.userService.createUser(createUserDto);
    }
    async updateUser(id, updateUserDto) {
        return await this.userService.updateUser(id, updateUserDto);
    }
    async recoverPassword(recoverPasswordDto) {
        return await this.userService.recoverPassword(recoverPasswordDto);
    }
    async deleteUser(id) {
        return await this.userService.deleteUser(id);
    }
};
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_a = typeof Promise !== "undefined" && Promise) === "function" ? _a : Object)
], UserController.prototype, "getUsers", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('byFilters'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof userSearchBody_type_1.UserSearchBody !== "undefined" && userSearchBody_type_1.UserSearchBody) === "function" ? _b : Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], UserController.prototype, "getUsersByFilters", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], UserController.prototype, "getUserById", null);
__decorate([
    (0, common_1.Post)('/'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_e = typeof createUser_dto_1.CreateUserDto !== "undefined" && createUser_dto_1.CreateUserDto) === "function" ? _e : Object]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], UserController.prototype, "createUser", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Put)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof updateUser_dto_1.UpdateUserDto !== "undefined" && updateUser_dto_1.UpdateUserDto) === "function" ? _g : Object]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], UserController.prototype, "updateUser", null);
__decorate([
    (0, common_1.Put)('password/recover'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_j = typeof recoverPassword_dto_1.RecoverPasswordDto !== "undefined" && recoverPassword_dto_1.RecoverPasswordDto) === "function" ? _j : Object]),
    __metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], UserController.prototype, "recoverPassword", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], UserController.prototype, "deleteUser", null);
UserController = __decorate([
    (0, common_1.Controller)('api/v1/users'),
    __metadata("design:paramtypes", [typeof (_m = typeof user_service_1.UserService !== "undefined" && user_service_1.UserService) === "function" ? _m : Object])
], UserController);
exports.UserController = UserController;


/***/ }),

/***/ "./apps/user/src/user.module.ts":
/*!**************************************!*\
  !*** ./apps/user/src/user.module.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const user_entity_1 = __webpack_require__(/*! ./entities/user.entity */ "./apps/user/src/entities/user.entity.ts");
const user_repository_1 = __webpack_require__(/*! ./repositories/user.repository */ "./apps/user/src/repositories/user.repository.ts");
const user_controller_1 = __webpack_require__(/*! ./user.controller */ "./apps/user/src/user.controller.ts");
const user_service_1 = __webpack_require__(/*! ./user.service */ "./apps/user/src/user.service.ts");
const elastic_search_module_1 = __webpack_require__(/*! ./elastic-search/elastic-search.module */ "./apps/user/src/elastic-search/elastic-search.module.ts");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const auth_module_1 = __webpack_require__(/*! apps/auth/src/auth.module */ "./apps/auth/src/auth.module.ts");
let UserModule = class UserModule {
};
UserModule = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true }),
            typeorm_1.TypeOrmModule.forRoot({
                type: 'mysql',
                host: 'mysql_user',
                database: 'users',
                port: 3306,
                username: 'root',
                password: 'root',
                entities: [user_entity_1.User],
                synchronize: true,
                autoLoadEntities: true,
                dropSchema: false,
                migrationsRun: false,
                logging: ['warn', 'error'],
                cli: {
                    migrationsDir: 'apps/user/src/migrations',
                },
            }),
            typeorm_1.TypeOrmModule.forFeature([user_repository_1.UserRepository]),
            elastic_search_module_1.ElasticSearchModule,
            (0, common_1.forwardRef)(() => auth_module_1.AuthModule),
        ],
        providers: [user_service_1.UserService],
        controllers: [user_controller_1.UserController],
        exports: [user_service_1.UserService],
    })
], UserModule);
exports.UserModule = UserModule;


/***/ }),

/***/ "./apps/user/src/user.service.ts":
/*!***************************************!*\
  !*** ./apps/user/src/user.service.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const elastic_search_service_1 = __webpack_require__(/*! ./elastic-search/elastic-search.service */ "./apps/user/src/elastic-search/elastic-search.service.ts");
const user_repository_1 = __webpack_require__(/*! ./repositories/user.repository */ "./apps/user/src/repositories/user.repository.ts");
let UserService = class UserService {
    constructor(userRepository, elasticSearchService) {
        this.userRepository = userRepository;
        this.elasticSearchService = elasticSearchService;
    }
    async getUsers(userSearchBody = null) {
        if (userSearchBody) {
            const { birthDate, createdAt, updatedAt } = userSearchBody;
            if (birthDate || createdAt || updatedAt) {
                return this.userRepository.findByFilters(userSearchBody);
            }
            else {
                let userSearchBodyList = [];
                let index = 1;
                for (const [attributeName, attributeValue] of Object.entries(userSearchBody)) {
                    if (attributeValue) {
                        const partialSearch = await this.elasticSearchService.search(attributeValue, [attributeName]);
                        userSearchBodyList =
                            index > 1
                                ? partialSearch.filter((item) => userSearchBodyList.includes(item))
                                : [...partialSearch];
                        index += 1;
                    }
                }
                return userSearchBodyList;
            }
        }
        else {
            return this.userRepository.findByFilters(null);
        }
    }
    async getUserById(id) {
        const user = await this.userRepository.findOne(id);
        if (!user) {
            throw new common_1.NotFoundException('Não existe um usuário com o id passado');
        }
        return user;
    }
    async createUser(createUserDto) {
        const { cpf, email, login } = createUserDto;
        const userAlreadyExist = await this.userRepository.userAlreadyExist(cpf, email, login);
        if (userAlreadyExist && userAlreadyExist.length) {
            throw new common_1.InternalServerErrorException(`Já existe um usuário cadastrado com o cpf, email ou login passados`);
        }
        try {
            await this.userRepository.createAndSave(createUserDto);
            const createdUser = await this.userRepository.findOne({
                where: { login },
            });
            this.elasticSearchService.index(createdUser);
            return createdUser;
        }
        catch (err) {
            throw new common_1.InternalServerErrorException(err.sqlMessage || err);
        }
    }
    async updateUser(id, updateUserDto) {
        const { cpf, email, login } = updateUserDto;
        const userAlreadyExist = await this.userRepository.userAlreadyExist(cpf, email, login);
        if (userAlreadyExist && userAlreadyExist.length) {
            const reallyAnotherUser = userAlreadyExist.find((user) => user.id !== id);
            if (reallyAnotherUser) {
                throw new common_1.InternalServerErrorException(`Já existe um usuário cadastrado com o cpf, email ou login passados`);
            }
        }
        const user = await this.userRepository.findOne(id);
        try {
            await this.userRepository.updateAndSave(user, updateUserDto);
            const updatedUser = await this.userRepository.findOne({
                where: { login },
            });
            return updatedUser;
        }
        catch (err) {
            throw new common_1.InternalServerErrorException(err.sqlMessage || err);
        }
    }
    async recoverPassword(recoverPasswordDto) {
        const { cpf, email, name, newPassword } = recoverPasswordDto;
        const user = await this.userRepository.findOne({
            where: {
                cpf,
            },
        });
        if (!user || user.email !== email || user.name !== name) {
            throw new common_1.ForbiddenException('As informações passadas estão incorretas');
        }
        try {
            await this.userRepository.changePasswordAndSave(user, newPassword);
            return user;
        }
        catch (err) {
            throw new common_1.InternalServerErrorException(err.sqlMessage || err);
        }
    }
    async findByLogin(login) {
        return await this.userRepository.findOne({
            where: {
                login,
            },
        });
    }
    async deleteUser(id) {
        try {
            const deleteResponse = await this.userRepository.delete(id);
            if (!deleteResponse.affected) {
                throw new common_1.NotFoundException('Usuário não encontrado');
            }
            await this.elasticSearchService.remove(id);
            return deleteResponse;
        }
        catch (err) {
            throw new common_1.InternalServerErrorException(err.sqlMessage || err);
        }
    }
};
UserService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof user_repository_1.UserRepository !== "undefined" && user_repository_1.UserRepository) === "function" ? _a : Object, typeof (_b = typeof elastic_search_service_1.ElasticSearchService !== "undefined" && elastic_search_service_1.ElasticSearchService) === "function" ? _b : Object])
], UserService);
exports.UserService = UserService;


/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/elasticsearch":
/*!****************************************!*\
  !*** external "@nestjs/elasticsearch" ***!
  \****************************************/
/***/ ((module) => {

module.exports = require("@nestjs/elasticsearch");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@nestjs/typeorm":
/*!**********************************!*\
  !*** external "@nestjs/typeorm" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/typeorm");

/***/ }),

/***/ "bcrypt":
/*!*************************!*\
  !*** external "bcrypt" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "passport-jwt":
/*!*******************************!*\
  !*** external "passport-jwt" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ }),

/***/ "typeorm":
/*!**************************!*\
  !*** external "typeorm" ***!
  \**************************/
/***/ ((module) => {

module.exports = require("typeorm");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!*******************************!*\
  !*** ./apps/auth/src/main.ts ***!
  \*******************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const auth_module_1 = __webpack_require__(/*! ./auth.module */ "./apps/auth/src/auth.module.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(auth_module_1.AuthModule);
    app.useGlobalPipes(new common_1.ValidationPipe());
    app.enableCors({ origin: ['http://localhost:4200'] });
    await app.listen(3001);
}
bootstrap();

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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RTNDLEtBQUssVUFBVSxTQUFTO0lBQ3RCLE1BQU0sR0FBRyxHQUFHLE1BQU0sa0JBQVcsQ0FBQyxNQUFNLENBQUMsd0JBQVUsQ0FBQyxDQUFDO0lBQ2pELEdBQUcsQ0FBQyxjQUFjLENBQUMsSUFBSSx1QkFBYyxFQUFFLENBQUMsQ0FBQztJQUN6QyxHQUFHLENBQUMsVUFBVSxDQUFDLEVBQUUsTUFBTSxFQUFFLENBQUMsdUJBQXVCLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDdEQsTUFBTSxHQUFHLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQ3pCLENBQUM7QUFDRCxTQUFTLEVBQUUsQ0FBQyIsInNvdXJjZXMiOlsid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9hdXRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9hdXRoLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2p3dC9qd3QtYXV0aC5ndWFyZC50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvand0L2p3dC5zdHJhdGVneS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL2NyZWF0ZVVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vbG9naW5Vc2VyLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL3JlY292ZXJQYXNzd29yZC5kdG8udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2R0by91cGRhdGVVc2VyLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2gubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5zZXJ2aWNlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbnRpdGllcy91c2VyLmVudGl0eS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZW51bXMvdXNlci1zdGF0dXMuZW51bS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvcmVwb3NpdG9yaWVzL3VzZXIucmVwb3NpdG9yeS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvdXNlci5jb250cm9sbGVyLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy91c2VyLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvdXNlci5zZXJ2aWNlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb25cIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29uZmlnXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvcmVcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvZWxhc3RpY3NlYXJjaFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9qd3RcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvcGFzc3BvcnRcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiYmNyeXB0XCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJjbGFzcy12YWxpZGF0b3JcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcInBhc3Nwb3J0LWp3dFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwidHlwZW9ybVwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIFBvc3QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBMb2dpblVzZXJEdG8gfSBmcm9tICdhcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvJztcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnO1xuXG5AQ29udHJvbGxlcignYXBpL3YxL2F1dGgnKVxuZXhwb3J0IGNsYXNzIEF1dGhDb250cm9sbGVyIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBhdXRoU2VydmljZTogQXV0aFNlcnZpY2UpIHt9XG5cbiAgQFBvc3QoJ2xvZ2luJylcbiAgYXN5bmMgbG9naW4oXG4gICAgQEJvZHkoKSBsb2dpblVzZXJEdG86IExvZ2luVXNlckR0byxcbiAgKTogUHJvbWlzZTx7IGFjY2Vzc1Rva2VuOiBzdHJpbmcgfT4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luVXNlckR0byk7XG4gIH1cbn1cbiIsImltcG9ydCB7IGZvcndhcmRSZWYsIE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IENvbmZpZ01vZHVsZSwgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJztcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0JztcbmltcG9ydCB7IFBhc3Nwb3J0TW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9wYXNzcG9ydCc7XG5pbXBvcnQgeyBVc2VyTW9kdWxlIH0gZnJvbSAnYXBwcy91c2VyL3NyYy91c2VyLm1vZHVsZSc7XG5pbXBvcnQgeyBBdXRoQ29udHJvbGxlciB9IGZyb20gJy4vYXV0aC5jb250cm9sbGVyJztcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnO1xuaW1wb3J0IHsgSnd0U3RyYXRlZ3kgfSBmcm9tICcuL2p3dC9qd3Quc3RyYXRlZ3knO1xuXG5ATW9kdWxlKHtcbiAgaW1wb3J0czogW1xuICAgIENvbmZpZ01vZHVsZS5mb3JSb290KHsgaXNHbG9iYWw6IHRydWUgfSksXG4gICAgUGFzc3BvcnRNb2R1bGUsXG4gICAgSnd0TW9kdWxlLnJlZ2lzdGVyQXN5bmMoe1xuICAgICAgaW1wb3J0czogW0NvbmZpZ01vZHVsZV0sXG4gICAgICB1c2VGYWN0b3J5OiBhc3luYyAoKSA9PiAoe1xuICAgICAgICBzZWNyZXQ6IHByb2Nlc3MuZW52LkpXVF9TRUNSRVQsXG4gICAgICB9KSxcbiAgICAgIGluamVjdDogW0NvbmZpZ1NlcnZpY2VdLFxuICAgIH0pLFxuICAgIGZvcndhcmRSZWYoKCkgPT4gVXNlck1vZHVsZSksXG4gIF0sXG4gIGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuICBwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0U3RyYXRlZ3ldLFxuICBleHBvcnRzOiBbQXV0aFNlcnZpY2UsIEp3dFN0cmF0ZWd5XSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7fVxuIiwiaW1wb3J0IHtcbiAgSW5qZWN0YWJsZSxcbiAgTm90Rm91bmRFeGNlcHRpb24sXG4gIFVuYXV0aG9yaXplZEV4Y2VwdGlvbixcbn0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgSnd0U2VydmljZSB9IGZyb20gJ0BuZXN0anMvand0JztcbmltcG9ydCB7IExvZ2luVXNlckR0byB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZHRvL2xvZ2luVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlciB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZW51bXMvdXNlci1zdGF0dXMuZW51bSc7XG5pbXBvcnQgeyBVc2VyU2VydmljZSB9IGZyb20gJ2FwcHMvdXNlci9zcmMvdXNlci5zZXJ2aWNlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcbiAgY29uc3RydWN0b3IoXG4gICAgcHJpdmF0ZSB1c2VyU2VydmljZTogVXNlclNlcnZpY2UsXG4gICAgcHJpdmF0ZSBqd3RTZXJ2aWNlOiBKd3RTZXJ2aWNlLFxuICApIHt9XG5cbiAgYXN5bmMgbG9naW4obG9naW5Vc2VyRHRvOiBMb2dpblVzZXJEdG8pOiBQcm9taXNlPHsgYWNjZXNzVG9rZW46IHN0cmluZyB9PiB7XG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudmFsaWRhdGVVc2VyKGxvZ2luVXNlckR0byk7XG5cbiAgICBjb25zdCBwYXlsb2FkID0ge1xuICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgIH07XG5cbiAgICByZXR1cm4ge1xuICAgICAgYWNjZXNzVG9rZW46IHRoaXMuand0U2VydmljZS5zaWduKHBheWxvYWQpLFxuICAgIH07XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZVVzZXIobG9naW5Vc2VyRHRvOiBMb2dpblVzZXJEdG8pOiBQcm9taXNlPFVzZXI+IHtcbiAgICBjb25zdCB7IGxvZ2luLCBwYXNzd29yZCB9ID0gbG9naW5Vc2VyRHRvO1xuXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZmluZEJ5TG9naW4obG9naW4pO1xuXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICB0aHJvdyBuZXcgTm90Rm91bmRFeGNlcHRpb24oJ1VzdcOhcmlvIG7Do28gZW5jb250cmFkbycpO1xuICAgIH1cblxuICAgIGlmICh1c2VyLnN0YXR1cyAhPT0gVXNlclN0YXR1cy5BY3RpdmUpIHtcbiAgICAgIHRocm93IG5ldyBVbmF1dGhvcml6ZWRFeGNlcHRpb24oXG4gICAgICAgIGBFc3NlIHVzdcOhcmlvIGVzdMOhIGNvbSBvIHN0YXR1cyAke3VzZXIuc3RhdHVzLnZhbHVlT2YoKX1gLFxuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCB2YWxpZGF0ZVBhc3N3b3JkID0gYXdhaXQgdXNlci52YWxpZGF0ZVBhc3N3b3JkKHBhc3N3b3JkKTtcblxuICAgIGlmICghdmFsaWRhdGVQYXNzd29yZCkge1xuICAgICAgdGhyb3cgbmV3IFVuYXV0aG9yaXplZEV4Y2VwdGlvbignTG9naW4gb3Ugc2VuaGEgaW5jb3JyZXRvcycpO1xuICAgIH1cblxuICAgIHJldHVybiB1c2VyO1xuICB9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgQXV0aEd1YXJkIH0gZnJvbSAnQG5lc3Rqcy9wYXNzcG9ydCc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBKd3RBdXRoR3VhcmQgZXh0ZW5kcyBBdXRoR3VhcmQoJ2p3dCcpIHt9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgUGFzc3BvcnRTdHJhdGVneSB9IGZyb20gJ0BuZXN0anMvcGFzc3BvcnQnO1xuaW1wb3J0IHsgRXh0cmFjdEp3dCwgU3RyYXRlZ3kgfSBmcm9tICdwYXNzcG9ydC1qd3QnO1xuaW1wb3J0IHsgSnd0UGF5bG9hZCB9IGZyb20gJy4vand0LnBheWxvYWQnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSnd0U3RyYXRlZ3kgZXh0ZW5kcyBQYXNzcG9ydFN0cmF0ZWd5KFN0cmF0ZWd5KSB7XG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHN1cGVyKHtcbiAgICAgIGp3dEZyb21SZXF1ZXN0OiBFeHRyYWN0Snd0LmZyb21BdXRoSGVhZGVyQXNCZWFyZXJUb2tlbigpLFxuICAgICAgaWdub3JlRXhwaXJhdGlvbjogZmFsc2UsXG4gICAgICBzZWNyZXRPcktleTogcHJvY2Vzcy5lbnYuSldUX1NFQ1JFVCxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIHZhbGlkYXRlKHBheWxvYWQ6IEp3dFBheWxvYWQpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiB7XG4gICAgICB1c2VySWQ6IHBheWxvYWQudXNlcklkLFxuICAgIH07XG4gIH1cbn1cbiIsImltcG9ydCB7XG4gIElzRW1haWwsXG4gIElzRW51bSxcbiAgSXNOb3RFbXB0eSxcbiAgSXNPcHRpb25hbCxcbiAgSXNQaG9uZU51bWJlcixcbiAgSXNTdHJpbmcsXG59IGZyb20gJ2NsYXNzLXZhbGlkYXRvcic7XG5pbXBvcnQgeyBVc2VyU3RhdHVzIH0gZnJvbSAnLi4vZW51bXMvdXNlci1zdGF0dXMuZW51bSc7XG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVVc2VyRHRvIHtcbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBuYW1lOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBsb2dpbjogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgcGFzc3dvcmQ6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc0VtYWlsKClcbiAgZW1haWw6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1Bob25lTnVtYmVyKClcbiAgcGhvbmVOdW1iZXI6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIGNwZjogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgYmlydGhEYXRlOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBtb3RoZXJOYW1lOiBzdHJpbmc7XG5cbiAgQElzT3B0aW9uYWwoKVxuICBASXNFbnVtKFVzZXJTdGF0dXMpXG4gIHN0YXR1czogVXNlclN0YXR1cztcbn1cbiIsImltcG9ydCB7IElzTm90RW1wdHkgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuXG5leHBvcnQgY2xhc3MgTG9naW5Vc2VyRHRvIHtcbiAgQElzTm90RW1wdHkoKVxuICBsb2dpbjogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgcGFzc3dvcmQ6IHN0cmluZztcbn1cbiIsImltcG9ydCB7XG4gIElzRW1haWwsXG4gIElzRW51bSxcbiAgSXNOb3RFbXB0eSxcbiAgSXNPcHRpb25hbCxcbiAgSXNQaG9uZU51bWJlcixcbiAgSXNTdHJpbmcsXG59IGZyb20gJ2NsYXNzLXZhbGlkYXRvcic7XG5leHBvcnQgY2xhc3MgUmVjb3ZlclBhc3N3b3JkRHRvIHtcbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBuYW1lOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNFbWFpbCgpXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBjcGY6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIG5ld1Bhc3N3b3JkOiBzdHJpbmc7XG59XG4iLCJpbXBvcnQgeyBDcmVhdGVVc2VyRHRvIH0gZnJvbSAnLi9jcmVhdGVVc2VyLmR0byc7XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVVc2VyRHRvIGV4dGVuZHMgQ3JlYXRlVXNlckR0byB7fVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlLCBDb25maWdTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgRWxhc3RpY1NlYXJjaFNlcnZpY2UgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoLnNlcnZpY2UnO1xuaW1wb3J0IHsgRWxhc3RpY3NlYXJjaE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvZWxhc3RpY3NlYXJjaCc7XG5cbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLFxuICAgIEVsYXN0aWNzZWFyY2hNb2R1bGUucmVnaXN0ZXJBc3luYyh7XG4gICAgICBpbXBvcnRzOiBbQ29uZmlnTW9kdWxlXSxcbiAgICAgIHVzZUZhY3Rvcnk6IGFzeW5jIChjb25maWdTZXJ2aWNlOiBDb25maWdTZXJ2aWNlKSA9PiAoe1xuICAgICAgICBub2RlOiBjb25maWdTZXJ2aWNlLmdldCgnRUxBU1RJQ1NFQVJDSF9OT0RFJyksXG4gICAgICAgIGF1dGg6IHtcbiAgICAgICAgICB1c2VybmFtZTogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfVVNFUk5BTUUnKSxcbiAgICAgICAgICBwYXNzd29yZDogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfUEFTU1dPUkQnKSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG4gICAgfSksXG4gIF0sXG4gIHByb3ZpZGVyczogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbiAgZXhwb3J0czogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgRWxhc3RpY1NlYXJjaE1vZHVsZSB7fVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEVsYXN0aWNzZWFyY2hTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9lbGFzdGljc2VhcmNoJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXJTZWFyY2hSZXN1bHQgfSBmcm9tICcuL2ludGVyZmFjZXMvdXNlclNlYXJjaFJlc3VsdC50eXBlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEVsYXN0aWNTZWFyY2hTZXJ2aWNlIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBlbGFzdGljc2VhcmNoU2VydmljZTogRWxhc3RpY3NlYXJjaFNlcnZpY2UpIHt9XG5cbiAgYXN5bmMgc2VhcmNoKHRleHQ6IHN0cmluZywgZmllbGRzOiBzdHJpbmdbXSk6IFByb21pc2U8VXNlclNlYXJjaEJvZHlbXT4ge1xuICAgIGNvbnN0IHsgYm9keSB9ID0gYXdhaXQgdGhpcy5lbGFzdGljc2VhcmNoU2VydmljZS5zZWFyY2g8VXNlclNlYXJjaFJlc3VsdD4oe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbXVsdGlfbWF0Y2g6IHtcbiAgICAgICAgICAgIHF1ZXJ5OiB0ZXh0LFxuICAgICAgICAgICAgZmllbGRzLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuICAgIGNvbnN0IGhpdHMgPSBib2R5LmhpdHMuaGl0cztcbiAgICByZXR1cm4gaGl0cy5tYXAoKGl0ZW0pID0+IGl0ZW0uX3NvdXJjZSk7XG4gIH1cblxuICBhc3luYyBpbmRleCh7IGlkLCBuYW1lLCBsb2dpbiwgY3BmLCBzdGF0dXMsIGJpcnRoRGF0ZSB9OiBVc2VyKSB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMuZWxhc3RpY3NlYXJjaFNlcnZpY2UuaW5kZXgoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIGlkLFxuICAgICAgICBuYW1lLFxuICAgICAgICBsb2dpbixcbiAgICAgICAgY3BmLFxuICAgICAgICBzdGF0dXMsXG4gICAgICAgIGJpcnRoRGF0ZSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyB1cGRhdGUodXNlcjogVXNlcikge1xuICAgIGF3YWl0IHRoaXMucmVtb3ZlKHVzZXIuaWQpO1xuICAgIGF3YWl0IHRoaXMuaW5kZXgodXNlcik7XG4gIH1cblxuICBhc3luYyByZW1vdmUodXNlcklkOiBzdHJpbmcpIHtcbiAgICB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmRlbGV0ZUJ5UXVlcnkoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgIGlkOiB1c2VySWQsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cbn1cbiIsImltcG9ydCB7XG4gIEVudGl0eSxcbiAgQ29sdW1uLFxuICBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLFxuICBCZWZvcmVJbnNlcnQsXG4gIFVwZGF0ZURhdGVDb2x1bW4sXG4gIEJlZm9yZVVwZGF0ZSxcbn0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgKiBhcyBiY3J5cHQgZnJvbSAnYmNyeXB0JztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5ARW50aXR5KClcbmV4cG9ydCBjbGFzcyBVc2VyIHtcbiAgQFByaW1hcnlHZW5lcmF0ZWRDb2x1bW4oJ3V1aWQnKVxuICBpZDogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBuYW1lOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIGxvZ2luOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInIH0pXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBob25lTnVtYmVyOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInIH0pXG4gIGNwZjogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ2RhdGUnKVxuICBiaXJ0aERhdGU6IHN0cmluZztcblxuICBAQ29sdW1uKCd2YXJjaGFyJylcbiAgbW90aGVyTmFtZTogc3RyaW5nO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IFVzZXJTdGF0dXMgfSlcbiAgc3RhdHVzOiBVc2VyU3RhdHVzO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAndGltZXN0YW1wJywgZGVmYXVsdDogKCkgPT4gJ0NVUlJFTlRfVElNRVNUQU1QJyB9KVxuICBjcmVhdGVkQXQ6IHN0cmluZztcblxuICBAVXBkYXRlRGF0ZUNvbHVtbih7IHR5cGU6ICd0aW1lc3RhbXAnIH0pXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xuXG4gIEBCZWZvcmVJbnNlcnQoKVxuICBAQmVmb3JlVXBkYXRlKClcbiAgYXN5bmMgaGFzaFBhc3N3b3JkKCkge1xuICAgIHRoaXMucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaCh0aGlzLnBhc3N3b3JkLCAxMik7XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZVBhc3N3b3JkKHBhc3N3b3JkOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICByZXR1cm4gYmNyeXB0LmNvbXBhcmUocGFzc3dvcmQsIHRoaXMucGFzc3dvcmQpO1xuICB9XG59XG4iLCJleHBvcnQgZW51bSBVc2VyU3RhdHVzIHtcbiAgQWN0aXZlID0gJ0F0aXZvJyxcbiAgQmxvY2tlZCA9ICdCbG9xdWVhZG8nLFxuICBJbmFjdGl2ZSA9ICdJbmF0aXZvJyxcbn1cbiIsImltcG9ydCB7IEVudGl0eVJlcG9zaXRvcnksIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXBkYXRlVXNlckR0byB9IGZyb20gJy4uL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4uL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi4vZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5ARW50aXR5UmVwb3NpdG9yeShVc2VyKVxuZXhwb3J0IGNsYXNzIFVzZXJSZXBvc2l0b3J5IGV4dGVuZHMgUmVwb3NpdG9yeTxVc2VyPiB7XG4gIGFzeW5jIGZpbmRCeUZpbHRlcnModXNlclNlYXJjaEJvZHk6IFVzZXJTZWFyY2hCb2R5KTogUHJvbWlzZTxVc2VyW10+IHtcbiAgICBpZiAodXNlclNlYXJjaEJvZHkpIHtcbiAgICAgIGNvbnN0IHtcbiAgICAgICAgbmFtZSxcbiAgICAgICAgbG9naW4sXG4gICAgICAgIGNwZixcbiAgICAgICAgc3RhdHVzLFxuICAgICAgICBhZ2VSYW5nZSxcbiAgICAgICAgYmlydGhEYXRlLFxuICAgICAgICBjcmVhdGVkQXQsXG4gICAgICAgIHVwZGF0ZWRBdCxcbiAgICAgIH0gPSB1c2VyU2VhcmNoQm9keTtcblxuICAgICAgY29uc3QgcXVlcnlCdWlsZGVyID0gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKTtcblxuICAgICAgbGV0IGZpcnN0V2hlcmUgPSB0cnVlO1xuXG4gICAgICBpZiAobmFtZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5uYW1lID0gOm5hbWUnLCB7IG5hbWUgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5uYW1lID0gOm5hbWUnLCB7IG5hbWUgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGxvZ2luKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmxvZ2luID0gOmxvZ2luJywgeyBsb2dpbiB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmxvZ2luID0gOmxvZ2luJywgeyBsb2dpbiB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoY3BmKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNwZiA9IDpjcGYnLCB7IGNwZiB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNwZiA9IDpjcGYnLCB7IGNwZiB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc3RhdHVzKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnN0YXR1cyA9IDpzdGF0dXMnLCB7IHN0YXR1cyB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnN0YXR1cyA9IDpzdGF0dXMnLCB7IHN0YXR1cyB9KTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnN0YXR1cyA9IDpzdGF0dXMnLCB7XG4gICAgICAgICAgc3RhdHVzOiBVc2VyU3RhdHVzLkFjdGl2ZSxcbiAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhd2FpdCBxdWVyeUJ1aWxkZXIuZ2V0TWFueSgpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKVxuICAgICAgICAud2hlcmUoJ3VzZXIuc3RhdHVzID0gOnN0YXR1cycsIHtcbiAgICAgICAgICBzdGF0dXM6IFVzZXJTdGF0dXMuQWN0aXZlLFxuICAgICAgICB9KVxuICAgICAgICAuZ2V0TWFueSgpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHVzZXJBbHJlYWR5RXhpc3QoXG4gICAgY3BmOiBzdHJpbmcsXG4gICAgZW1haWw6IHN0cmluZyxcbiAgICBsb2dpbjogc3RyaW5nLFxuICApOiBQcm9taXNlPFVzZXJbXT4ge1xuICAgIHJldHVybiB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigndXNlcicpXG4gICAgICAud2hlcmUoJ3VzZXIuY3BmID0gOmNwZicsIHsgY3BmIH0pXG4gICAgICAub3JXaGVyZSgndXNlci5lbWFpbCA9IDplbWFpbCcsIHsgZW1haWwgfSlcbiAgICAgIC5vcldoZXJlKCd1c2VyLmxvZ2luID0gOmxvZ2luJywgeyBsb2dpbiB9KVxuICAgICAgLmdldE1hbnkoKTtcbiAgfVxuXG4gIGFzeW5jIGNyZWF0ZUFuZFNhdmUoe1xuICAgIG5hbWUsXG4gICAgbG9naW4sXG4gICAgcGFzc3dvcmQsXG4gICAgZW1haWwsXG4gICAgcGhvbmVOdW1iZXIsXG4gICAgY3BmLFxuICAgIGJpcnRoRGF0ZSxcbiAgICBtb3RoZXJOYW1lLFxuICAgIHN0YXR1cyxcbiAgfTogQ3JlYXRlVXNlckR0bykge1xuICAgIGNvbnN0IHVzZXIgPSB0aGlzLmNyZWF0ZSgpO1xuXG4gICAgdXNlci5uYW1lID0gbmFtZTtcbiAgICB1c2VyLmxvZ2luID0gbG9naW47XG4gICAgdXNlci5wYXNzd29yZCA9IHBhc3N3b3JkO1xuICAgIHVzZXIuZW1haWwgPSBlbWFpbDtcbiAgICB1c2VyLnBob25lTnVtYmVyID0gcGhvbmVOdW1iZXI7XG4gICAgdXNlci5jcGYgPSBjcGY7XG4gICAgdXNlci5iaXJ0aERhdGUgPSBiaXJ0aERhdGU7XG4gICAgdXNlci5tb3RoZXJOYW1lID0gbW90aGVyTmFtZTtcbiAgICB1c2VyLnN0YXR1cyA9IHN0YXR1cztcblxuICAgIGF3YWl0IHRoaXMuaW5zZXJ0KHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgdXBkYXRlQW5kU2F2ZShcbiAgICB1c2VyOiBVc2VyLFxuICAgIHtcbiAgICAgIG5hbWUsXG4gICAgICBsb2dpbixcbiAgICAgIHBhc3N3b3JkLFxuICAgICAgZW1haWwsXG4gICAgICBwaG9uZU51bWJlcixcbiAgICAgIGNwZixcbiAgICAgIGJpcnRoRGF0ZSxcbiAgICAgIG1vdGhlck5hbWUsXG4gICAgICBzdGF0dXMsXG4gICAgfTogVXBkYXRlVXNlckR0byxcbiAgKSB7XG4gICAgdXNlci5uYW1lID0gbmFtZSB8fCB1c2VyLm5hbWU7XG4gICAgdXNlci5sb2dpbiA9IGxvZ2luIHx8IHVzZXIubG9naW47XG4gICAgdXNlci5wYXNzd29yZCA9IHBhc3N3b3JkIHx8IHVzZXIucGFzc3dvcmQ7XG4gICAgdXNlci5lbWFpbCA9IGVtYWlsIHx8IHVzZXIuZW1haWw7XG4gICAgdXNlci5waG9uZU51bWJlciA9IHBob25lTnVtYmVyIHx8IHVzZXIucGhvbmVOdW1iZXI7XG4gICAgdXNlci5jcGYgPSBjcGYgfHwgdXNlci5jcGY7XG4gICAgdXNlci5iaXJ0aERhdGUgPSBiaXJ0aERhdGUgfHwgdXNlci5iaXJ0aERhdGU7XG4gICAgdXNlci5tb3RoZXJOYW1lID0gbW90aGVyTmFtZSB8fCB1c2VyLm1vdGhlck5hbWU7XG4gICAgdXNlci5zdGF0dXMgPSBzdGF0dXMgfHwgdXNlci5zdGF0dXM7XG5cbiAgICBhd2FpdCB0aGlzLnNhdmUodXNlcik7XG4gIH1cblxuICBhc3luYyBjaGFuZ2VQYXNzd29yZEFuZFNhdmUodXNlcjogVXNlciwgbmV3UGFzc3dvcmQ6IHN0cmluZykge1xuICAgIHVzZXIucGFzc3dvcmQgPSBuZXdQYXNzd29yZDtcbiAgICBhd2FpdCB0aGlzLnNhdmUodXNlcik7XG4gIH1cbn1cbiIsImltcG9ydCB7XG4gIEJvZHksXG4gIENvbnRyb2xsZXIsXG4gIERlbGV0ZSxcbiAgR2V0LFxuICBPbk1vZHVsZUluaXQsXG4gIFBhcmFtLFxuICBQb3N0LFxuICBQdXQsXG4gIFVzZUd1YXJkcyxcbn0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgSnd0QXV0aEd1YXJkIH0gZnJvbSAnYXBwcy9hdXRoL3NyYy9qd3Qvand0LWF1dGguZ3VhcmQnO1xuaW1wb3J0IHsgRGVsZXRlUmVzdWx0IH0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgeyBDcmVhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgUmVjb3ZlclBhc3N3b3JkRHRvIH0gZnJvbSAnLi9kdG8vcmVjb3ZlclBhc3N3b3JkLmR0byc7XG5pbXBvcnQgeyBVcGRhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyU2VydmljZSB9IGZyb20gJy4vdXNlci5zZXJ2aWNlJztcblxuQENvbnRyb2xsZXIoJ2FwaS92MS91c2VycycpXG5leHBvcnQgY2xhc3MgVXNlckNvbnRyb2xsZXIge1xuICBjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IHVzZXJTZXJ2aWNlOiBVc2VyU2VydmljZSkge31cblxuICAvLyBTZXJ2acOnbyBxdWUgcmV0b3JuYSB0b2RvcyBvcyB1c3XDoXJpb3NcbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBHZXQoKVxuICBhc3luYyBnZXRVc2VycygpOiBQcm9taXNlPFVzZXJbXSB8IFVzZXJTZWFyY2hCb2R5W10+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5nZXRVc2VycygpO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIHJldG9ybmEgb3MgdXN1w6FyaW9zIGRlIGZvcm1hIHBhZ2luYWRhLCBwb3NzaWJpbGl0YW5kbyBpbnNlcmlyIGZpbHRyb3MgbmEgYnVzY2FcbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBQb3N0KCdieUZpbHRlcnMnKVxuICBhc3luYyBnZXRVc2Vyc0J5RmlsdGVycyhcbiAgICBAQm9keSgpIHVzZXJTZWFyY2hCb2R5OiBVc2VyU2VhcmNoQm9keSxcbiAgKTogUHJvbWlzZTxVc2VyW10gfCBVc2VyU2VhcmNoQm9keVtdPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZ2V0VXNlcnModXNlclNlYXJjaEJvZHkpO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIHJldG9ybmEgdW0gdXN1w6FyaW8gcGVsbyBzZXUgaWRcbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBHZXQoJzppZCcpXG4gIGFzeW5jIGdldFVzZXJCeUlkKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZ2V0VXNlckJ5SWQoaWQpO1xuICB9XG5cbiAgLy8gU2VydmnDp28gZGUgY3JpYcOnw6NvIGRlIHVtIHVzdcOhcmlvXG4gIEBQb3N0KCcvJylcbiAgYXN5bmMgY3JlYXRlVXNlcihAQm9keSgpIGNyZWF0ZVVzZXJEdG86IENyZWF0ZVVzZXJEdG8pOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5jcmVhdGVVc2VyKGNyZWF0ZVVzZXJEdG8pO1xuICB9XG5cbiAgLy8gU2VydmnDp28gZGUgYXR1YWxpemHDp8OjbyBkZSB1bSB1c3XDoXJpb1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQFB1dCgnOmlkJylcbiAgYXN5bmMgdXBkYXRlVXNlcihcbiAgICBAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZyxcbiAgICBAQm9keSgpIHVwZGF0ZVVzZXJEdG86IFVwZGF0ZVVzZXJEdG8sXG4gICk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLnVwZGF0ZVVzZXIoaWQsIHVwZGF0ZVVzZXJEdG8pO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIHBlcm1pdGUgYSB1bSB1c3XDoXJpbyByZWN1cGVyYXIgbyBzZXUgYWNlc3NvIGFsdGVyYW5kbyBhIHNlbmhhXG4gIEBQdXQoJ3Bhc3N3b3JkL3JlY292ZXInKVxuICBhc3luYyByZWNvdmVyUGFzc3dvcmQoXG4gICAgQEJvZHkoKSByZWNvdmVyUGFzc3dvcmREdG86IFJlY292ZXJQYXNzd29yZER0byxcbiAgKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UucmVjb3ZlclBhc3N3b3JkKHJlY292ZXJQYXNzd29yZER0byk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBxdWUgZXhjbHVpIHVtIHVzdcOhcmlvXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBARGVsZXRlKCc6aWQnKVxuICBhc3luYyBkZWxldGVVc2VyKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKTogUHJvbWlzZTxEZWxldGVSZXN1bHQ+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5kZWxldGVVc2VyKGlkKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgZm9yd2FyZFJlZiwgR2xvYmFsLCBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJSZXBvc2l0b3J5IH0gZnJvbSAnLi9yZXBvc2l0b3JpZXMvdXNlci5yZXBvc2l0b3J5JztcbmltcG9ydCB7IFVzZXJDb250cm9sbGVyIH0gZnJvbSAnLi91c2VyLmNvbnRyb2xsZXInO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICcuL3VzZXIuc2VydmljZSc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoTW9kdWxlIH0gZnJvbSAnLi9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5tb2R1bGUnO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJ2FwcHMvYXV0aC9zcmMvYXV0aC5tb2R1bGUnO1xuXG5AR2xvYmFsKClcbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLmZvclJvb3QoeyBpc0dsb2JhbDogdHJ1ZSB9KSxcbiAgICBUeXBlT3JtTW9kdWxlLmZvclJvb3Qoe1xuICAgICAgdHlwZTogJ215c3FsJyxcbiAgICAgIGhvc3Q6ICdteXNxbF91c2VyJyxcbiAgICAgIGRhdGFiYXNlOiAndXNlcnMnLFxuICAgICAgcG9ydDogMzMwNixcbiAgICAgIHVzZXJuYW1lOiAncm9vdCcsXG4gICAgICBwYXNzd29yZDogJ3Jvb3QnLFxuICAgICAgZW50aXRpZXM6IFtVc2VyXSxcbiAgICAgIHN5bmNocm9uaXplOiB0cnVlLFxuICAgICAgYXV0b0xvYWRFbnRpdGllczogdHJ1ZSxcbiAgICAgIGRyb3BTY2hlbWE6IGZhbHNlLFxuICAgICAgbWlncmF0aW9uc1J1bjogZmFsc2UsXG4gICAgICBsb2dnaW5nOiBbJ3dhcm4nLCAnZXJyb3InXSxcbiAgICAgIGNsaToge1xuICAgICAgICBtaWdyYXRpb25zRGlyOiAnYXBwcy91c2VyL3NyYy9taWdyYXRpb25zJyxcbiAgICAgIH0sXG4gICAgfSksXG4gICAgVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtVc2VyUmVwb3NpdG9yeV0pLFxuICAgIEVsYXN0aWNTZWFyY2hNb2R1bGUsXG4gICAgZm9yd2FyZFJlZigoKSA9PiBBdXRoTW9kdWxlKSxcbiAgXSxcbiAgcHJvdmlkZXJzOiBbVXNlclNlcnZpY2VdLFxuICBjb250cm9sbGVyczogW1VzZXJDb250cm9sbGVyXSxcbiAgZXhwb3J0czogW1VzZXJTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgVXNlck1vZHVsZSB7fVxuIiwiaW1wb3J0IHtcbiAgRm9yYmlkZGVuRXhjZXB0aW9uLFxuICBJbmplY3RhYmxlLFxuICBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uLFxuICBOb3RGb3VuZEV4Y2VwdGlvbixcbn0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgRGVsZXRlUmVzdWx0IH0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgeyBDcmVhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgUmVjb3ZlclBhc3N3b3JkRHRvIH0gZnJvbSAnLi9kdG8vcmVjb3ZlclBhc3N3b3JkLmR0byc7XG5pbXBvcnQgeyBVcGRhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgRWxhc3RpY1NlYXJjaFNlcnZpY2UgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoL2VsYXN0aWMtc2VhcmNoLnNlcnZpY2UnO1xuaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyUmVwb3NpdG9yeSB9IGZyb20gJy4vcmVwb3NpdG9yaWVzL3VzZXIucmVwb3NpdG9yeSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVc2VyU2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHByaXZhdGUgdXNlclJlcG9zaXRvcnk6IFVzZXJSZXBvc2l0b3J5LFxuICAgIHByaXZhdGUgZWxhc3RpY1NlYXJjaFNlcnZpY2U6IEVsYXN0aWNTZWFyY2hTZXJ2aWNlLFxuICApIHt9XG5cbiAgYXN5bmMgZ2V0VXNlcnMoXG4gICAgdXNlclNlYXJjaEJvZHk6IFVzZXJTZWFyY2hCb2R5ID0gbnVsbCxcbiAgKTogUHJvbWlzZTxVc2VyW10gfCBVc2VyU2VhcmNoQm9keVtdPiB7XG4gICAgaWYgKHVzZXJTZWFyY2hCb2R5KSB7XG4gICAgICBjb25zdCB7IGJpcnRoRGF0ZSwgY3JlYXRlZEF0LCB1cGRhdGVkQXQgfSA9IHVzZXJTZWFyY2hCb2R5O1xuXG4gICAgICBpZiAoYmlydGhEYXRlIHx8IGNyZWF0ZWRBdCB8fCB1cGRhdGVkQXQpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMudXNlclJlcG9zaXRvcnkuZmluZEJ5RmlsdGVycyh1c2VyU2VhcmNoQm9keSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsZXQgdXNlclNlYXJjaEJvZHlMaXN0OiBVc2VyU2VhcmNoQm9keVtdID0gW107XG5cbiAgICAgICAgbGV0IGluZGV4ID0gMTtcblxuICAgICAgICBmb3IgKGNvbnN0IFthdHRyaWJ1dGVOYW1lLCBhdHRyaWJ1dGVWYWx1ZV0gb2YgT2JqZWN0LmVudHJpZXMoXG4gICAgICAgICAgdXNlclNlYXJjaEJvZHksXG4gICAgICAgICkpIHtcbiAgICAgICAgICBpZiAoYXR0cmlidXRlVmFsdWUpIHtcbiAgICAgICAgICAgIGNvbnN0IHBhcnRpYWxTZWFyY2ggPSBhd2FpdCB0aGlzLmVsYXN0aWNTZWFyY2hTZXJ2aWNlLnNlYXJjaChcbiAgICAgICAgICAgICAgYXR0cmlidXRlVmFsdWUsXG4gICAgICAgICAgICAgIFthdHRyaWJ1dGVOYW1lXSxcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QgPVxuICAgICAgICAgICAgICBpbmRleCA+IDFcbiAgICAgICAgICAgICAgICA/IHBhcnRpYWxTZWFyY2guZmlsdGVyKChpdGVtKSA9PlxuICAgICAgICAgICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QuaW5jbHVkZXMoaXRlbSksXG4gICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgOiBbLi4ucGFydGlhbFNlYXJjaF07XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB1c2VyU2VhcmNoQm9keUxpc3Q7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRCeUZpbHRlcnMobnVsbCk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgZ2V0VXNlckJ5SWQoaWQ6IHN0cmluZyk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoaWQpO1xuXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICB0aHJvdyBuZXcgTm90Rm91bmRFeGNlcHRpb24oJ07Do28gZXhpc3RlIHVtIHVzdcOhcmlvIGNvbSBvIGlkIHBhc3NhZG8nKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdXNlcjtcbiAgfVxuXG4gIGFzeW5jIGNyZWF0ZVVzZXIoY3JlYXRlVXNlckR0bzogQ3JlYXRlVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgY3BmLCBlbWFpbCwgbG9naW4gfSA9IGNyZWF0ZVVzZXJEdG87XG5cbiAgICBjb25zdCB1c2VyQWxyZWFkeUV4aXN0ID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51c2VyQWxyZWFkeUV4aXN0KFxuICAgICAgY3BmLFxuICAgICAgZW1haWwsXG4gICAgICBsb2dpbixcbiAgICApO1xuXG4gICAgaWYgKHVzZXJBbHJlYWR5RXhpc3QgJiYgdXNlckFscmVhZHlFeGlzdC5sZW5ndGgpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKFxuICAgICAgICBgSsOhIGV4aXN0ZSB1bSB1c3XDoXJpbyBjYWRhc3RyYWRvIGNvbSBvIGNwZiwgZW1haWwgb3UgbG9naW4gcGFzc2Fkb3NgLFxuICAgICAgKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5jcmVhdGVBbmRTYXZlKGNyZWF0ZVVzZXJEdG8pO1xuXG4gICAgICBjb25zdCBjcmVhdGVkVXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICAgIHdoZXJlOiB7IGxvZ2luIH0sXG4gICAgICB9KTtcblxuICAgICAgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS5pbmRleChjcmVhdGVkVXNlcik7XG5cbiAgICAgIHJldHVybiBjcmVhdGVkVXNlcjtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgdXBkYXRlVXNlcihpZDogc3RyaW5nLCB1cGRhdGVVc2VyRHRvOiBVcGRhdGVVc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBjcGYsIGVtYWlsLCBsb2dpbiB9ID0gdXBkYXRlVXNlckR0bztcblxuICAgIGNvbnN0IHVzZXJBbHJlYWR5RXhpc3QgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LnVzZXJBbHJlYWR5RXhpc3QoXG4gICAgICBjcGYsXG4gICAgICBlbWFpbCxcbiAgICAgIGxvZ2luLFxuICAgICk7XG5cbiAgICBpZiAodXNlckFscmVhZHlFeGlzdCAmJiB1c2VyQWxyZWFkeUV4aXN0Lmxlbmd0aCkge1xuICAgICAgY29uc3QgcmVhbGx5QW5vdGhlclVzZXIgPSB1c2VyQWxyZWFkeUV4aXN0LmZpbmQoKHVzZXIpID0+IHVzZXIuaWQgIT09IGlkKTtcblxuICAgICAgaWYgKHJlYWxseUFub3RoZXJVc2VyKSB7XG4gICAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKFxuICAgICAgICAgIGBKw6EgZXhpc3RlIHVtIHVzdcOhcmlvIGNhZGFzdHJhZG8gY29tIG8gY3BmLCBlbWFpbCBvdSBsb2dpbiBwYXNzYWRvc2AsXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZShpZCk7XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51cGRhdGVBbmRTYXZlKHVzZXIsIHVwZGF0ZVVzZXJEdG8pO1xuXG4gICAgICBjb25zdCB1cGRhdGVkVXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICAgIHdoZXJlOiB7IGxvZ2luIH0sXG4gICAgICB9KTtcblxuICAgICAgLy8gYXdhaXQgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS51cGRhdGUodXBkYXRlZFVzZXIpO1xuXG4gICAgICByZXR1cm4gdXBkYXRlZFVzZXI7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHJlY292ZXJQYXNzd29yZChyZWNvdmVyUGFzc3dvcmREdG86IFJlY292ZXJQYXNzd29yZER0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgY3BmLCBlbWFpbCwgbmFtZSwgbmV3UGFzc3dvcmQgfSA9IHJlY292ZXJQYXNzd29yZER0bztcblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgd2hlcmU6IHtcbiAgICAgICAgY3BmLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsICE9PSBlbWFpbCB8fCB1c2VyLm5hbWUgIT09IG5hbWUpIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FeGNlcHRpb24oJ0FzIGluZm9ybWHDp8O1ZXMgcGFzc2FkYXMgZXN0w6NvIGluY29ycmV0YXMnKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5jaGFuZ2VQYXNzd29yZEFuZFNhdmUodXNlciwgbmV3UGFzc3dvcmQpO1xuXG4gICAgICByZXR1cm4gdXNlcjtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgZmluZEJ5TG9naW4obG9naW46IHN0cmluZyk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgd2hlcmU6IHtcbiAgICAgICAgbG9naW4sXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgZGVsZXRlVXNlcihpZDogc3RyaW5nKTogUHJvbWlzZTxEZWxldGVSZXN1bHQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGVsZXRlUmVzcG9uc2UgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmRlbGV0ZShpZCk7XG5cbiAgICAgIGlmICghZGVsZXRlUmVzcG9uc2UuYWZmZWN0ZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IE5vdEZvdW5kRXhjZXB0aW9uKCdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS5yZW1vdmUoaWQpO1xuXG4gICAgICByZXR1cm4gZGVsZXRlUmVzcG9uc2U7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvZWxhc3RpY3NlYXJjaFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2p3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Bhc3Nwb3J0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInBhc3Nwb3J0LWp3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJ0eXBlb3JtXCIpOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0uY2FsbChtb2R1bGUuZXhwb3J0cywgbW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCJpbXBvcnQgeyBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IE5lc3RGYWN0b3J5IH0gZnJvbSAnQG5lc3Rqcy9jb3JlJztcbmltcG9ydCB7IEF1dGhNb2R1bGUgfSBmcm9tICcuL2F1dGgubW9kdWxlJztcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuICBjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoQXV0aE1vZHVsZSk7XG4gIGFwcC51c2VHbG9iYWxQaXBlcyhuZXcgVmFsaWRhdGlvblBpcGUoKSk7XG4gIGFwcC5lbmFibGVDb3JzKHsgb3JpZ2luOiBbJ2h0dHA6Ly9sb2NhbGhvc3Q6NDIwMCddIH0pO1xuICBhd2FpdCBhcHAubGlzdGVuKDMwMDEpO1xufVxuYm9vdHN0cmFwKCk7XG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=