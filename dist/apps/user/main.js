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
exports.UpdateUserDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const createUser_dto_1 = __webpack_require__(/*! ./createUser.dto */ "./apps/user/src/dto/createUser.dto.ts");
class UpdateUserDto extends createUser_dto_1.CreateUserDto {
}
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UpdateUserDto.prototype, "password", void 0);
exports.UpdateUserDto = UpdateUserDto;


/***/ }),

/***/ "./apps/user/src/dto/userResponse.dto.ts":
/*!***********************************************!*\
  !*** ./apps/user/src/dto/userResponse.dto.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserResponseDto = void 0;
class UserResponseDto {
    constructor(data, count) {
        this.data = data;
        this.count = count;
    }
}
exports.UserResponseDto = UserResponseDto;


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
    async search(first, size, text, fields) {
        const { body } = await this.elasticsearchService.search({
            index: 'users',
            from: first,
            size,
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
    async count(text, fields) {
        const { body } = await this.elasticsearchService.count({
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
        return body;
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
    async findByFilters(userSearchBody, first = 0, size = 0) {
        if (userSearchBody) {
            const { name, login, cpf, status, ageRange, birthDate, createdAt, updatedAt, } = userSearchBody;
            const queryBuilder = this.createQueryBuilder('user');
            let firstWhere = true;
            if (name) {
                if (firstWhere) {
                    queryBuilder.where('user.name like :name', { name: `%${name}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.name like :name', { name: `%${name}%` });
                }
            }
            if (login) {
                if (firstWhere) {
                    queryBuilder.where('user.login like :login', { login: `%${login}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.login like :login', {
                        login: `%${login}%`,
                    });
                }
            }
            if (cpf) {
                if (firstWhere) {
                    queryBuilder.where('user.cpf like :cpf', { cpf: `%${cpf}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.cpf like :cpf', { cpf: `%${cpf}%` });
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
            if (ageRange) {
                if (firstWhere) {
                    queryBuilder.where('user.ageRange = :ageRange', { ageRange });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.ageRange = :ageRange', { ageRange });
                }
            }
            if (birthDate) {
                if (firstWhere) {
                    queryBuilder.where('user.birthDate = :birthDate', { birthDate });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.birthDate = :birthDate', { birthDate });
                }
            }
            if (createdAt) {
                if (firstWhere) {
                    queryBuilder.where('user.createdAt = :createdAt', { createdAt });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.createdAt = :createdAt', { createdAt });
                }
            }
            if (updatedAt) {
                if (firstWhere) {
                    queryBuilder.where('user.updatedAt = :updatedAt', { updatedAt });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.updatedAt = :updatedAt', { updatedAt });
                }
            }
            queryBuilder.skip(first).take(size);
            return await queryBuilder.getMany();
        }
        else {
            return this.createQueryBuilder('user')
                .where('user.status != :status', {
                status: user_status_enum_1.UserStatus.Inactive,
            })
                .skip(first)
                .take(size)
                .getMany();
        }
    }
    async countByFilters(userSearchBody) {
        if (userSearchBody) {
            const { name, login, cpf, status, ageRange, birthDate, createdAt, updatedAt, } = userSearchBody;
            const queryBuilder = this.createQueryBuilder('user');
            let firstWhere = true;
            if (name) {
                if (firstWhere) {
                    queryBuilder.where('user.name like :name', { name: `%${name}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.name like :name', { name: `%${name}%` });
                }
            }
            if (login) {
                if (firstWhere) {
                    queryBuilder.where('user.login like :login', { login: `%${login}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.login like :login', {
                        login: `%${login}%`,
                    });
                }
            }
            if (cpf) {
                if (firstWhere) {
                    queryBuilder.where('user.cpf like :cpf', { cpf: `%${cpf}%` });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.cpf like :cpf', { cpf: `%${cpf}%` });
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
            if (ageRange) {
                if (firstWhere) {
                    queryBuilder.where('user.ageRange = :ageRange', { ageRange });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.ageRange = :ageRange', { ageRange });
                }
            }
            if (birthDate) {
                if (firstWhere) {
                    queryBuilder.where('user.birthDate = :birthDate', { birthDate });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.birthDate = :birthDate', { birthDate });
                }
            }
            if (createdAt) {
                if (firstWhere) {
                    queryBuilder.where('user.createdAt = :createdAt', { createdAt });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.createdAt = :createdAt', { createdAt });
                }
            }
            if (updatedAt) {
                if (firstWhere) {
                    queryBuilder.where('user.updatedAt = :updatedAt', { updatedAt });
                    firstWhere = false;
                }
                else {
                    queryBuilder.andWhere('user.updatedAt = :updatedAt', { updatedAt });
                }
            }
            return await queryBuilder.getCount();
        }
        else {
            return this.createQueryBuilder('user')
                .where('user.status != :status', {
                status: user_status_enum_1.UserStatus.Inactive,
            })
                .getCount();
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
    async inactiveAllUsers() {
        await this.createQueryBuilder()
            .update(user_entity_1.User)
            .set({ status: user_status_enum_1.UserStatus.Inactive })
            .execute();
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
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o;
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
    async getUsersByFilters(userSearchBody, first, size) {
        return await this.userService.getUsers(first, size, userSearchBody);
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
    async changeUserStatus(id, { status }) {
        return await this.userService.changeUserStatus(id, status);
    }
    async inactiveUserBulk() {
        return await this.userService.inactiveUserBulk();
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
    __param(1, (0, common_1.Param)('first')),
    __param(2, (0, common_1.Param)('size')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof userSearchBody_type_1.UserSearchBody !== "undefined" && userSearchBody_type_1.UserSearchBody) === "function" ? _b : Object, Number, Number]),
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
    (0, common_1.Put)(':id/status'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], UserController.prototype, "changeUserStatus", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Delete)('inactive'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], UserController.prototype, "inactiveUserBulk", null);
UserController = __decorate([
    (0, common_1.Controller)('api/v1/users'),
    __metadata("design:paramtypes", [typeof (_o = typeof user_service_1.UserService !== "undefined" && user_service_1.UserService) === "function" ? _o : Object])
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
const updateUser_dto_1 = __webpack_require__(/*! ./dto/updateUser.dto */ "./apps/user/src/dto/updateUser.dto.ts");
const userResponse_dto_1 = __webpack_require__(/*! ./dto/userResponse.dto */ "./apps/user/src/dto/userResponse.dto.ts");
const elastic_search_service_1 = __webpack_require__(/*! ./elastic-search/elastic-search.service */ "./apps/user/src/elastic-search/elastic-search.service.ts");
const user_repository_1 = __webpack_require__(/*! ./repositories/user.repository */ "./apps/user/src/repositories/user.repository.ts");
let UserService = class UserService {
    constructor(userRepository, elasticSearchService) {
        this.userRepository = userRepository;
        this.elasticSearchService = elasticSearchService;
    }
    async getUsers(first = 0, size = 0, userSearchBody = null) {
        if (userSearchBody) {
            const { birthDate, createdAt, updatedAt } = userSearchBody;
            if (birthDate || createdAt || updatedAt || true) {
                const users = await this.userRepository.findByFilters(userSearchBody, first, size);
                const count = await this.userRepository.countByFilters(userSearchBody);
                const userResponseDto = new userResponse_dto_1.UserResponseDto(users, count);
                return userResponseDto;
            }
            else {}
        }
        else {
            const users = await this.userRepository.findByFilters(userSearchBody, first, size);
            const count = await this.userRepository.countByFilters(userSearchBody);
            const userResponseDto = new userResponse_dto_1.UserResponseDto(users, count);
            return userResponseDto;
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
    async changeUserStatus(id, userStatus) {
        const user = await this.userRepository.findOne(id);
        if (!user) {
            throw new common_1.NotFoundException('Usuário não existe');
        }
        try {
            const updateUserDto = new updateUser_dto_1.UpdateUserDto();
            updateUserDto.status = userStatus;
            await this.userRepository.updateAndSave(user, updateUserDto);
            const userChangeResult = {
                affected: 1,
            };
            return userChangeResult;
        }
        catch (err) {
            throw new common_1.InternalServerErrorException(err.sqlMessage || err);
        }
    }
    async inactiveUserBulk() {
        try {
            console.log('here');
            return await this.userRepository.inactiveAllUsers();
        }
        catch (err) {
            console.log(err);
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
  !*** ./apps/user/src/main.ts ***!
  \*******************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const user_module_1 = __webpack_require__(/*! ./user.module */ "./apps/user/src/user.module.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(user_module_1.UserModule);
    app.useGlobalPipes(new common_1.ValidationPipe());
    app.enableCors({ origin: ['http://localhost:4200'] });
    await app.listen(3000);
}
bootstrap();

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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Ozs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7O1VDQUE7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7Ozs7Ozs7Ozs7O0FDdEJBLDZFQUFnRDtBQUNoRCx1RUFBMkM7QUFDM0MsaUdBQTJDO0FBRTNDLEtBQUssVUFBVSxTQUFTO0lBQ3RCLE1BQU0sR0FBRyxHQUFHLE1BQU0sa0JBQVcsQ0FBQyxNQUFNLENBQUMsd0JBQVUsQ0FBQyxDQUFDO0lBQ2pELEdBQUcsQ0FBQyxjQUFjLENBQUMsSUFBSSx1QkFBYyxFQUFFLENBQUMsQ0FBQztJQUN6QyxHQUFHLENBQUMsVUFBVSxDQUFDLEVBQUUsTUFBTSxFQUFFLENBQUMsdUJBQXVCLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDdEQsTUFBTSxHQUFHLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQ3pCLENBQUM7QUFDRCxTQUFTLEVBQUUsQ0FBQyIsInNvdXJjZXMiOlsid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9hdXRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9hdXRoLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2p3dC9qd3QtYXV0aC5ndWFyZC50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvand0L2p3dC5zdHJhdGVneS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL2NyZWF0ZVVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vbG9naW5Vc2VyLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL3JlY292ZXJQYXNzd29yZC5kdG8udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2R0by91cGRhdGVVc2VyLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL3VzZXJSZXNwb25zZS5kdG8udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2VsYXN0aWMtc2VhcmNoL2VsYXN0aWMtc2VhcmNoLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2guc2VydmljZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZW50aXRpZXMvdXNlci5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2VudW1zL3VzZXItc3RhdHVzLmVudW0udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL3JlcG9zaXRvcmllcy91c2VyLnJlcG9zaXRvcnkudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL3VzZXIuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvdXNlci5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL3VzZXIuc2VydmljZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbmZpZ1wiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb3JlXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2VsYXN0aWNzZWFyY2hcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvand0XCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3Bhc3Nwb3J0XCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3R5cGVvcm1cIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJwYXNzcG9ydC1qd3RcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcInR5cGVvcm1cIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvbWFpbi50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBQb3N0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgTG9naW5Vc2VyRHRvIH0gZnJvbSAnYXBwcy91c2VyL3NyYy9kdG8vbG9naW5Vc2VyLmR0byc7XG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJztcblxuQENvbnRyb2xsZXIoJ2FwaS92MS9hdXRoJylcbmV4cG9ydCBjbGFzcyBBdXRoQ29udHJvbGxlciB7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgYXV0aFNlcnZpY2U6IEF1dGhTZXJ2aWNlKSB7fVxuXG4gIEBQb3N0KCdsb2dpbicpXG4gIGFzeW5jIGxvZ2luKFxuICAgIEBCb2R5KCkgbG9naW5Vc2VyRHRvOiBMb2dpblVzZXJEdG8sXG4gICk6IFByb21pc2U8eyBhY2Nlc3NUb2tlbjogc3RyaW5nIH0+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5sb2dpbihsb2dpblVzZXJEdG8pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBmb3J3YXJkUmVmLCBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1NlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2NvbmZpZyc7XG5pbXBvcnQgeyBKd3RNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2p3dCc7XG5pbXBvcnQgeyBQYXNzcG9ydE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvcGFzc3BvcnQnO1xuaW1wb3J0IHsgVXNlck1vZHVsZSB9IGZyb20gJ2FwcHMvdXNlci9zcmMvdXNlci5tb2R1bGUnO1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcic7XG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJztcbmltcG9ydCB7IEp3dFN0cmF0ZWd5IH0gZnJvbSAnLi9qd3Qvand0LnN0cmF0ZWd5JztcblxuQE1vZHVsZSh7XG4gIGltcG9ydHM6IFtcbiAgICBDb25maWdNb2R1bGUuZm9yUm9vdCh7IGlzR2xvYmFsOiB0cnVlIH0pLFxuICAgIFBhc3Nwb3J0TW9kdWxlLFxuICAgIEp3dE1vZHVsZS5yZWdpc3RlckFzeW5jKHtcbiAgICAgIGltcG9ydHM6IFtDb25maWdNb2R1bGVdLFxuICAgICAgdXNlRmFjdG9yeTogYXN5bmMgKCkgPT4gKHtcbiAgICAgICAgc2VjcmV0OiBwcm9jZXNzLmVudi5KV1RfU0VDUkVULFxuICAgICAgfSksXG4gICAgICBpbmplY3Q6IFtDb25maWdTZXJ2aWNlXSxcbiAgICB9KSxcbiAgICBmb3J3YXJkUmVmKCgpID0+IFVzZXJNb2R1bGUpLFxuICBdLFxuICBjb250cm9sbGVyczogW0F1dGhDb250cm9sbGVyXSxcbiAgcHJvdmlkZXJzOiBbQXV0aFNlcnZpY2UsIEp3dFN0cmF0ZWd5XSxcbiAgZXhwb3J0czogW0F1dGhTZXJ2aWNlLCBKd3RTdHJhdGVneV0sXG59KVxuZXhwb3J0IGNsYXNzIEF1dGhNb2R1bGUge31cbiIsImltcG9ydCB7XG4gIEluamVjdGFibGUsXG4gIE5vdEZvdW5kRXhjZXB0aW9uLFxuICBVbmF1dGhvcml6ZWRFeGNlcHRpb24sXG59IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEp3dFNlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2p3dCc7XG5pbXBvcnQgeyBMb2dpblVzZXJEdG8gfSBmcm9tICdhcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICdhcHBzL3VzZXIvc3JjL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICdhcHBzL3VzZXIvc3JjL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICdhcHBzL3VzZXIvc3JjL3VzZXIuc2VydmljZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdXRoU2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHByaXZhdGUgdXNlclNlcnZpY2U6IFVzZXJTZXJ2aWNlLFxuICAgIHByaXZhdGUgand0U2VydmljZTogSnd0U2VydmljZSxcbiAgKSB7fVxuXG4gIGFzeW5jIGxvZ2luKGxvZ2luVXNlckR0bzogTG9naW5Vc2VyRHRvKTogUHJvbWlzZTx7IGFjY2Vzc1Rva2VuOiBzdHJpbmcgfT4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnZhbGlkYXRlVXNlcihsb2dpblVzZXJEdG8pO1xuXG4gICAgY29uc3QgcGF5bG9hZCA9IHtcbiAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICB9O1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGFjY2Vzc1Rva2VuOiB0aGlzLmp3dFNlcnZpY2Uuc2lnbihwYXlsb2FkKSxcbiAgICB9O1xuICB9XG5cbiAgYXN5bmMgdmFsaWRhdGVVc2VyKGxvZ2luVXNlckR0bzogTG9naW5Vc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBsb2dpbiwgcGFzc3dvcmQgfSA9IGxvZ2luVXNlckR0bztcblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmZpbmRCeUxvZ2luKGxvZ2luKTtcblxuICAgIGlmICghdXNlcikge1xuICAgICAgdGhyb3cgbmV3IE5vdEZvdW5kRXhjZXB0aW9uKCdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nKTtcbiAgICB9XG5cbiAgICBpZiAodXNlci5zdGF0dXMgIT09IFVzZXJTdGF0dXMuQWN0aXZlKSB7XG4gICAgICB0aHJvdyBuZXcgVW5hdXRob3JpemVkRXhjZXB0aW9uKFxuICAgICAgICBgRXNzZSB1c3XDoXJpbyBlc3TDoSBjb20gbyBzdGF0dXMgJHt1c2VyLnN0YXR1cy52YWx1ZU9mKCl9YCxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgY29uc3QgdmFsaWRhdGVQYXNzd29yZCA9IGF3YWl0IHVzZXIudmFsaWRhdGVQYXNzd29yZChwYXNzd29yZCk7XG5cbiAgICBpZiAoIXZhbGlkYXRlUGFzc3dvcmQpIHtcbiAgICAgIHRocm93IG5ldyBVbmF1dGhvcml6ZWRFeGNlcHRpb24oJ0xvZ2luIG91IHNlbmhhIGluY29ycmV0b3MnKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdXNlcjtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEF1dGhHdWFyZCB9IGZyb20gJ0BuZXN0anMvcGFzc3BvcnQnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSnd0QXV0aEd1YXJkIGV4dGVuZHMgQXV0aEd1YXJkKCdqd3QnKSB7fVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IFBhc3Nwb3J0U3RyYXRlZ3kgfSBmcm9tICdAbmVzdGpzL3Bhc3Nwb3J0JztcbmltcG9ydCB7IEV4dHJhY3RKd3QsIFN0cmF0ZWd5IH0gZnJvbSAncGFzc3BvcnQtand0JztcbmltcG9ydCB7IEp3dFBheWxvYWQgfSBmcm9tICcuL2p3dC5wYXlsb2FkJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEp3dFN0cmF0ZWd5IGV4dGVuZHMgUGFzc3BvcnRTdHJhdGVneShTdHJhdGVneSkge1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICBzdXBlcih7XG4gICAgICBqd3RGcm9tUmVxdWVzdDogRXh0cmFjdEp3dC5mcm9tQXV0aEhlYWRlckFzQmVhcmVyVG9rZW4oKSxcbiAgICAgIGlnbm9yZUV4cGlyYXRpb246IGZhbHNlLFxuICAgICAgc2VjcmV0T3JLZXk6IHByb2Nlc3MuZW52LkpXVF9TRUNSRVQsXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZShwYXlsb2FkOiBKd3RQYXlsb2FkKTogUHJvbWlzZTxhbnk+IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXNlcklkOiBwYXlsb2FkLnVzZXJJZCxcbiAgICB9O1xuICB9XG59XG4iLCJpbXBvcnQge1xuICBJc0VtYWlsLFxuICBJc0VudW0sXG4gIElzTm90RW1wdHksXG4gIElzT3B0aW9uYWwsXG4gIElzUGhvbmVOdW1iZXIsXG4gIElzU3RyaW5nLFxufSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlVXNlckR0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbmFtZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbG9naW46IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNFbWFpbCgpXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNQaG9uZU51bWJlcigpXG4gIHBob25lTnVtYmVyOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBjcGY6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIGJpcnRoRGF0ZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbW90aGVyTmFtZTogc3RyaW5nO1xuXG4gIEBJc09wdGlvbmFsKClcbiAgQElzRW51bShVc2VyU3RhdHVzKVxuICBzdGF0dXM6IFVzZXJTdGF0dXM7XG59XG4iLCJpbXBvcnQgeyBJc05vdEVtcHR5IH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJztcblxuZXhwb3J0IGNsYXNzIExvZ2luVXNlckR0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgbG9naW46IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG59XG4iLCJpbXBvcnQge1xuICBJc0VtYWlsLFxuICBJc0VudW0sXG4gIElzTm90RW1wdHksXG4gIElzT3B0aW9uYWwsXG4gIElzUGhvbmVOdW1iZXIsXG4gIElzU3RyaW5nLFxufSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuZXhwb3J0IGNsYXNzIFJlY292ZXJQYXNzd29yZER0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbmFtZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzRW1haWwoKVxuICBlbWFpbDogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgY3BmOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBuZXdQYXNzd29yZDogc3RyaW5nO1xufVxuIiwiaW1wb3J0IHsgSXNTdHJpbmcgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuaW1wb3J0IHsgQ3JlYXRlVXNlckR0byB9IGZyb20gJy4vY3JlYXRlVXNlci5kdG8nO1xuXG5leHBvcnQgY2xhc3MgVXBkYXRlVXNlckR0byBleHRlbmRzIENyZWF0ZVVzZXJEdG8ge1xuICBASXNTdHJpbmcoKVxuICBwYXNzd29yZDogc3RyaW5nO1xufVxuIiwiaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuLi9lbGFzdGljLXNlYXJjaC9pbnRlcmZhY2VzL3VzZXJTZWFyY2hCb2R5LnR5cGUnO1xuaW1wb3J0IHsgVXNlciB9IGZyb20gJy4uL2VudGl0aWVzL3VzZXIuZW50aXR5JztcblxuZXhwb3J0IGNsYXNzIFVzZXJSZXNwb25zZUR0byB7XG4gIGRhdGE6IFVzZXJbXSB8IFVzZXJTZWFyY2hCb2R5W107XG4gIGNvdW50OiBudW1iZXI7XG5cbiAgcHVibGljIGNvbnN0cnVjdG9yKGRhdGE6IFVzZXJbXSB8IFVzZXJTZWFyY2hCb2R5W10sIGNvdW50OiBudW1iZXIpIHtcbiAgICB0aGlzLmRhdGEgPSBkYXRhO1xuICAgIHRoaXMuY291bnQgPSBjb3VudDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlLCBDb25maWdTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgRWxhc3RpY1NlYXJjaFNlcnZpY2UgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoLnNlcnZpY2UnO1xuaW1wb3J0IHsgRWxhc3RpY3NlYXJjaE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvZWxhc3RpY3NlYXJjaCc7XG5cbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLFxuICAgIEVsYXN0aWNzZWFyY2hNb2R1bGUucmVnaXN0ZXJBc3luYyh7XG4gICAgICBpbXBvcnRzOiBbQ29uZmlnTW9kdWxlXSxcbiAgICAgIHVzZUZhY3Rvcnk6IGFzeW5jIChjb25maWdTZXJ2aWNlOiBDb25maWdTZXJ2aWNlKSA9PiAoe1xuICAgICAgICBub2RlOiBjb25maWdTZXJ2aWNlLmdldCgnRUxBU1RJQ1NFQVJDSF9OT0RFJyksXG4gICAgICAgIGF1dGg6IHtcbiAgICAgICAgICB1c2VybmFtZTogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfVVNFUk5BTUUnKSxcbiAgICAgICAgICBwYXNzd29yZDogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfUEFTU1dPUkQnKSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG4gICAgfSksXG4gIF0sXG4gIHByb3ZpZGVyczogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbiAgZXhwb3J0czogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgRWxhc3RpY1NlYXJjaE1vZHVsZSB7fVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEVsYXN0aWNzZWFyY2hTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9lbGFzdGljc2VhcmNoJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyQ291bnRSZXN1bHQgfSBmcm9tICcuL2ludGVyZmFjZXMvdXNlckNvdW50UmVzdWx0LnR5cGUnO1xuaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoUmVzdWx0IH0gZnJvbSAnLi9pbnRlcmZhY2VzL3VzZXJTZWFyY2hSZXN1bHQudHlwZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbGFzdGljU2VhcmNoU2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZWxhc3RpY3NlYXJjaFNlcnZpY2U6IEVsYXN0aWNzZWFyY2hTZXJ2aWNlKSB7fVxuXG4gIGFzeW5jIHNlYXJjaChcbiAgICBmaXJzdDogbnVtYmVyLFxuICAgIHNpemU6IG51bWJlcixcbiAgICB0ZXh0OiBzdHJpbmcsXG4gICAgZmllbGRzOiBzdHJpbmdbXSxcbiAgKTogUHJvbWlzZTxVc2VyU2VhcmNoQm9keVtdPiB7XG4gICAgY29uc3QgeyBib2R5IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLnNlYXJjaDxVc2VyU2VhcmNoUmVzdWx0Pih7XG4gICAgICBpbmRleDogJ3VzZXJzJyxcbiAgICAgIGZyb206IGZpcnN0LFxuICAgICAgc2l6ZSxcbiAgICAgIGJvZHk6IHtcbiAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICBtdWx0aV9tYXRjaDoge1xuICAgICAgICAgICAgcXVlcnk6IHRleHQsXG4gICAgICAgICAgICBmaWVsZHMsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gICAgY29uc3QgaGl0cyA9IGJvZHkuaGl0cy5oaXRzO1xuICAgIHJldHVybiBoaXRzLm1hcCgoaXRlbSkgPT4gaXRlbS5fc291cmNlKTtcbiAgfVxuXG4gIGFzeW5jIGNvdW50KHRleHQ6IHN0cmluZywgZmllbGRzOiBzdHJpbmdbXSk6IFByb21pc2U8VXNlckNvdW50UmVzdWx0PiB7XG4gICAgY29uc3QgeyBib2R5IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmNvdW50PFVzZXJDb3VudFJlc3VsdD4oe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbXVsdGlfbWF0Y2g6IHtcbiAgICAgICAgICAgIHF1ZXJ5OiB0ZXh0LFxuICAgICAgICAgICAgZmllbGRzLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIGJvZHk7XG4gIH1cblxuICBhc3luYyBpbmRleCh7IGlkLCBuYW1lLCBsb2dpbiwgY3BmLCBzdGF0dXMsIGJpcnRoRGF0ZSB9OiBVc2VyKSB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMuZWxhc3RpY3NlYXJjaFNlcnZpY2UuaW5kZXgoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIGlkLFxuICAgICAgICBuYW1lLFxuICAgICAgICBsb2dpbixcbiAgICAgICAgY3BmLFxuICAgICAgICBzdGF0dXMsXG4gICAgICAgIGJpcnRoRGF0ZSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyB1cGRhdGUodXNlcjogVXNlcikge1xuICAgIGF3YWl0IHRoaXMucmVtb3ZlKHVzZXIuaWQpO1xuICAgIGF3YWl0IHRoaXMuaW5kZXgodXNlcik7XG4gIH1cblxuICBhc3luYyByZW1vdmUodXNlcklkOiBzdHJpbmcpIHtcbiAgICB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmRlbGV0ZUJ5UXVlcnkoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgIGlkOiB1c2VySWQsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cbn1cbiIsImltcG9ydCB7XG4gIEVudGl0eSxcbiAgQ29sdW1uLFxuICBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLFxuICBCZWZvcmVJbnNlcnQsXG4gIFVwZGF0ZURhdGVDb2x1bW4sXG4gIEJlZm9yZVVwZGF0ZSxcbn0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgKiBhcyBiY3J5cHQgZnJvbSAnYmNyeXB0JztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5ARW50aXR5KClcbmV4cG9ydCBjbGFzcyBVc2VyIHtcbiAgQFByaW1hcnlHZW5lcmF0ZWRDb2x1bW4oJ3V1aWQnKVxuICBpZDogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBuYW1lOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIGxvZ2luOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInIH0pXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBob25lTnVtYmVyOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInIH0pXG4gIGNwZjogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ2RhdGUnKVxuICBiaXJ0aERhdGU6IHN0cmluZztcblxuICBAQ29sdW1uKCd2YXJjaGFyJylcbiAgbW90aGVyTmFtZTogc3RyaW5nO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IFVzZXJTdGF0dXMgfSlcbiAgc3RhdHVzOiBVc2VyU3RhdHVzO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAndGltZXN0YW1wJywgZGVmYXVsdDogKCkgPT4gJ0NVUlJFTlRfVElNRVNUQU1QJyB9KVxuICBjcmVhdGVkQXQ6IHN0cmluZztcblxuICBAVXBkYXRlRGF0ZUNvbHVtbih7IHR5cGU6ICd0aW1lc3RhbXAnIH0pXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xuXG4gIEBCZWZvcmVJbnNlcnQoKVxuICBAQmVmb3JlVXBkYXRlKClcbiAgYXN5bmMgaGFzaFBhc3N3b3JkKCkge1xuICAgIHRoaXMucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaCh0aGlzLnBhc3N3b3JkLCAxMik7XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZVBhc3N3b3JkKHBhc3N3b3JkOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICByZXR1cm4gYmNyeXB0LmNvbXBhcmUocGFzc3dvcmQsIHRoaXMucGFzc3dvcmQpO1xuICB9XG59XG4iLCJleHBvcnQgZW51bSBVc2VyU3RhdHVzIHtcbiAgQWN0aXZlID0gJ0F0aXZvJyxcbiAgQmxvY2tlZCA9ICdCbG9xdWVhZG8nLFxuICBJbmFjdGl2ZSA9ICdJbmF0aXZvJyxcbn1cbiIsImltcG9ydCB7IEVudGl0eVJlcG9zaXRvcnksIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXBkYXRlVXNlckR0byB9IGZyb20gJy4uL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4uL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi4vZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5ARW50aXR5UmVwb3NpdG9yeShVc2VyKVxuZXhwb3J0IGNsYXNzIFVzZXJSZXBvc2l0b3J5IGV4dGVuZHMgUmVwb3NpdG9yeTxVc2VyPiB7XG4gIGFzeW5jIGZpbmRCeUZpbHRlcnMoXG4gICAgdXNlclNlYXJjaEJvZHk6IFVzZXJTZWFyY2hCb2R5LFxuICAgIGZpcnN0ID0gMCxcbiAgICBzaXplID0gMCxcbiAgKTogUHJvbWlzZTxVc2VyW10+IHtcbiAgICBpZiAodXNlclNlYXJjaEJvZHkpIHtcbiAgICAgIGNvbnN0IHtcbiAgICAgICAgbmFtZSxcbiAgICAgICAgbG9naW4sXG4gICAgICAgIGNwZixcbiAgICAgICAgc3RhdHVzLFxuICAgICAgICBhZ2VSYW5nZSxcbiAgICAgICAgYmlydGhEYXRlLFxuICAgICAgICBjcmVhdGVkQXQsXG4gICAgICAgIHVwZGF0ZWRBdCxcbiAgICAgIH0gPSB1c2VyU2VhcmNoQm9keTtcblxuICAgICAgY29uc3QgcXVlcnlCdWlsZGVyID0gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKTtcblxuICAgICAgbGV0IGZpcnN0V2hlcmUgPSB0cnVlO1xuXG4gICAgICBpZiAobmFtZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5uYW1lIGxpa2UgOm5hbWUnLCB7IG5hbWU6IGAlJHtuYW1lfSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIubmFtZSBsaWtlIDpuYW1lJywgeyBuYW1lOiBgJSR7bmFtZX0lYCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAobG9naW4pIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIubG9naW4gbGlrZSA6bG9naW4nLCB7IGxvZ2luOiBgJSR7bG9naW59JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5sb2dpbiBsaWtlIDpsb2dpbicsIHtcbiAgICAgICAgICAgIGxvZ2luOiBgJSR7bG9naW59JWAsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGNwZikge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHN0YXR1cykge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGFnZVJhbmdlKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmFnZVJhbmdlID0gOmFnZVJhbmdlJywgeyBhZ2VSYW5nZSB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmFnZVJhbmdlID0gOmFnZVJhbmdlJywgeyBhZ2VSYW5nZSB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoYmlydGhEYXRlKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmJpcnRoRGF0ZSA9IDpiaXJ0aERhdGUnLCB7IGJpcnRoRGF0ZSB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmJpcnRoRGF0ZSA9IDpiaXJ0aERhdGUnLCB7IGJpcnRoRGF0ZSB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoY3JlYXRlZEF0KSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNyZWF0ZWRBdCA9IDpjcmVhdGVkQXQnLCB7IGNyZWF0ZWRBdCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNyZWF0ZWRBdCA9IDpjcmVhdGVkQXQnLCB7IGNyZWF0ZWRBdCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAodXBkYXRlZEF0KSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnVwZGF0ZWRBdCA9IDp1cGRhdGVkQXQnLCB7IHVwZGF0ZWRBdCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnVwZGF0ZWRBdCA9IDp1cGRhdGVkQXQnLCB7IHVwZGF0ZWRBdCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBxdWVyeUJ1aWxkZXIuc2tpcChmaXJzdCkudGFrZShzaXplKTtcblxuICAgICAgcmV0dXJuIGF3YWl0IHF1ZXJ5QnVpbGRlci5nZXRNYW55KCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigndXNlcicpXG4gICAgICAgIC53aGVyZSgndXNlci5zdGF0dXMgIT0gOnN0YXR1cycsIHtcbiAgICAgICAgICBzdGF0dXM6IFVzZXJTdGF0dXMuSW5hY3RpdmUsXG4gICAgICAgIH0pXG4gICAgICAgIC5za2lwKGZpcnN0KVxuICAgICAgICAudGFrZShzaXplKVxuICAgICAgICAuZ2V0TWFueSgpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5OiBVc2VyU2VhcmNoQm9keSk6IFByb21pc2U8bnVtYmVyPiB7XG4gICAgaWYgKHVzZXJTZWFyY2hCb2R5KSB7XG4gICAgICBjb25zdCB7XG4gICAgICAgIG5hbWUsXG4gICAgICAgIGxvZ2luLFxuICAgICAgICBjcGYsXG4gICAgICAgIHN0YXR1cyxcbiAgICAgICAgYWdlUmFuZ2UsXG4gICAgICAgIGJpcnRoRGF0ZSxcbiAgICAgICAgY3JlYXRlZEF0LFxuICAgICAgICB1cGRhdGVkQXQsXG4gICAgICB9ID0gdXNlclNlYXJjaEJvZHk7XG5cbiAgICAgIGNvbnN0IHF1ZXJ5QnVpbGRlciA9IHRoaXMuY3JlYXRlUXVlcnlCdWlsZGVyKCd1c2VyJyk7XG5cbiAgICAgIGxldCBmaXJzdFdoZXJlID0gdHJ1ZTtcblxuICAgICAgaWYgKG5hbWUpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIubmFtZSBsaWtlIDpuYW1lJywgeyBuYW1lOiBgJSR7bmFtZX0lYCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLm5hbWUgbGlrZSA6bmFtZScsIHsgbmFtZTogYCUke25hbWV9JWAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGxvZ2luKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmxvZ2luIGxpa2UgOmxvZ2luJywgeyBsb2dpbjogYCUke2xvZ2lufSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIubG9naW4gbGlrZSA6bG9naW4nLCB7XG4gICAgICAgICAgICBsb2dpbjogYCUke2xvZ2lufSVgLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChjcGYpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuY3BmIGxpa2UgOmNwZicsIHsgY3BmOiBgJSR7Y3BmfSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuY3BmIGxpa2UgOmNwZicsIHsgY3BmOiBgJSR7Y3BmfSVgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChzdGF0dXMpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuc3RhdHVzID0gOnN0YXR1cycsIHsgc3RhdHVzIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuc3RhdHVzID0gOnN0YXR1cycsIHsgc3RhdHVzIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChhZ2VSYW5nZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5hZ2VSYW5nZSA9IDphZ2VSYW5nZScsIHsgYWdlUmFuZ2UgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5hZ2VSYW5nZSA9IDphZ2VSYW5nZScsIHsgYWdlUmFuZ2UgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGJpcnRoRGF0ZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5iaXJ0aERhdGUgPSA6YmlydGhEYXRlJywgeyBiaXJ0aERhdGUgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5iaXJ0aERhdGUgPSA6YmlydGhEYXRlJywgeyBiaXJ0aERhdGUgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGNyZWF0ZWRBdCkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcmVhdGVkQXQgPSA6Y3JlYXRlZEF0JywgeyBjcmVhdGVkQXQgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcmVhdGVkQXQgPSA6Y3JlYXRlZEF0JywgeyBjcmVhdGVkQXQgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHVwZGF0ZWRBdCkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci51cGRhdGVkQXQgPSA6dXBkYXRlZEF0JywgeyB1cGRhdGVkQXQgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci51cGRhdGVkQXQgPSA6dXBkYXRlZEF0JywgeyB1cGRhdGVkQXQgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGF3YWl0IHF1ZXJ5QnVpbGRlci5nZXRDb3VudCgpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKVxuICAgICAgICAud2hlcmUoJ3VzZXIuc3RhdHVzICE9IDpzdGF0dXMnLCB7XG4gICAgICAgICAgc3RhdHVzOiBVc2VyU3RhdHVzLkluYWN0aXZlLFxuICAgICAgICB9KVxuICAgICAgICAuZ2V0Q291bnQoKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyB1c2VyQWxyZWFkeUV4aXN0KFxuICAgIGNwZjogc3RyaW5nLFxuICAgIGVtYWlsOiBzdHJpbmcsXG4gICAgbG9naW46IHN0cmluZyxcbiAgKTogUHJvbWlzZTxVc2VyW10+IHtcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKVxuICAgICAgLndoZXJlKCd1c2VyLmNwZiA9IDpjcGYnLCB7IGNwZiB9KVxuICAgICAgLm9yV2hlcmUoJ3VzZXIuZW1haWwgPSA6ZW1haWwnLCB7IGVtYWlsIH0pXG4gICAgICAub3JXaGVyZSgndXNlci5sb2dpbiA9IDpsb2dpbicsIHsgbG9naW4gfSlcbiAgICAgIC5nZXRNYW55KCk7XG4gIH1cblxuICBhc3luYyBjcmVhdGVBbmRTYXZlKHtcbiAgICBuYW1lLFxuICAgIGxvZ2luLFxuICAgIHBhc3N3b3JkLFxuICAgIGVtYWlsLFxuICAgIHBob25lTnVtYmVyLFxuICAgIGNwZixcbiAgICBiaXJ0aERhdGUsXG4gICAgbW90aGVyTmFtZSxcbiAgICBzdGF0dXMsXG4gIH06IENyZWF0ZVVzZXJEdG8pIHtcbiAgICBjb25zdCB1c2VyID0gdGhpcy5jcmVhdGUoKTtcblxuICAgIHVzZXIubmFtZSA9IG5hbWU7XG4gICAgdXNlci5sb2dpbiA9IGxvZ2luO1xuICAgIHVzZXIucGFzc3dvcmQgPSBwYXNzd29yZDtcbiAgICB1c2VyLmVtYWlsID0gZW1haWw7XG4gICAgdXNlci5waG9uZU51bWJlciA9IHBob25lTnVtYmVyO1xuICAgIHVzZXIuY3BmID0gY3BmO1xuICAgIHVzZXIuYmlydGhEYXRlID0gYmlydGhEYXRlO1xuICAgIHVzZXIubW90aGVyTmFtZSA9IG1vdGhlck5hbWU7XG4gICAgdXNlci5zdGF0dXMgPSBzdGF0dXM7XG5cbiAgICBhd2FpdCB0aGlzLmluc2VydCh1c2VyKTtcbiAgfVxuXG4gIGFzeW5jIHVwZGF0ZUFuZFNhdmUoXG4gICAgdXNlcjogVXNlcixcbiAgICB7XG4gICAgICBuYW1lLFxuICAgICAgbG9naW4sXG4gICAgICBwYXNzd29yZCxcbiAgICAgIGVtYWlsLFxuICAgICAgcGhvbmVOdW1iZXIsXG4gICAgICBjcGYsXG4gICAgICBiaXJ0aERhdGUsXG4gICAgICBtb3RoZXJOYW1lLFxuICAgICAgc3RhdHVzLFxuICAgIH06IFVwZGF0ZVVzZXJEdG8sXG4gICkge1xuICAgIHVzZXIubmFtZSA9IG5hbWUgfHwgdXNlci5uYW1lO1xuICAgIHVzZXIubG9naW4gPSBsb2dpbiB8fCB1c2VyLmxvZ2luO1xuICAgIHVzZXIucGFzc3dvcmQgPSBwYXNzd29yZCB8fCB1c2VyLnBhc3N3b3JkO1xuICAgIHVzZXIuZW1haWwgPSBlbWFpbCB8fCB1c2VyLmVtYWlsO1xuICAgIHVzZXIucGhvbmVOdW1iZXIgPSBwaG9uZU51bWJlciB8fCB1c2VyLnBob25lTnVtYmVyO1xuICAgIHVzZXIuY3BmID0gY3BmIHx8IHVzZXIuY3BmO1xuICAgIHVzZXIuYmlydGhEYXRlID0gYmlydGhEYXRlIHx8IHVzZXIuYmlydGhEYXRlO1xuICAgIHVzZXIubW90aGVyTmFtZSA9IG1vdGhlck5hbWUgfHwgdXNlci5tb3RoZXJOYW1lO1xuICAgIHVzZXIuc3RhdHVzID0gc3RhdHVzIHx8IHVzZXIuc3RhdHVzO1xuXG4gICAgYXdhaXQgdGhpcy5zYXZlKHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgY2hhbmdlUGFzc3dvcmRBbmRTYXZlKHVzZXI6IFVzZXIsIG5ld1Bhc3N3b3JkOiBzdHJpbmcpIHtcbiAgICB1c2VyLnBhc3N3b3JkID0gbmV3UGFzc3dvcmQ7XG4gICAgYXdhaXQgdGhpcy5zYXZlKHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgaW5hY3RpdmVBbGxVc2VycygpIHtcbiAgICBhd2FpdCB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigpXG4gICAgICAudXBkYXRlKFVzZXIpXG4gICAgICAuc2V0KHsgc3RhdHVzOiBVc2VyU3RhdHVzLkluYWN0aXZlIH0pXG4gICAgICAuZXhlY3V0ZSgpO1xuICB9XG59XG4iLCJpbXBvcnQge1xuICBCb2R5LFxuICBDb250cm9sbGVyLFxuICBEZWxldGUsXG4gIEdldCxcbiAgUGFyYW0sXG4gIFBvc3QsXG4gIFB1dCxcbiAgVXNlR3VhcmRzLFxufSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBKd3RBdXRoR3VhcmQgfSBmcm9tICdhcHBzL2F1dGgvc3JjL2p3dC9qd3QtYXV0aC5ndWFyZCc7XG5pbXBvcnQgeyBEZWxldGVSZXN1bHQgfSBmcm9tICd0eXBlb3JtJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBSZWNvdmVyUGFzc3dvcmREdG8gfSBmcm9tICcuL2R0by9yZWNvdmVyUGFzc3dvcmQuZHRvJztcbmltcG9ydCB7IFVwZGF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyQ2hhbmdlUmVzdWx0IH0gZnJvbSAnLi9kdG8vdXNlckNoYW5nZVJlc3VsdC5kdG8nO1xuaW1wb3J0IHsgVXNlclJlc3BvbnNlRHRvIH0gZnJvbSAnLi9kdG8vdXNlclJlc3BvbnNlLmR0byc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICcuL3VzZXIuc2VydmljZSc7XG5cbkBDb250cm9sbGVyKCdhcGkvdjEvdXNlcnMnKVxuZXhwb3J0IGNsYXNzIFVzZXJDb250cm9sbGVyIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSB1c2VyU2VydmljZTogVXNlclNlcnZpY2UpIHt9XG5cbiAgLy8gU2VydmnDp28gcXVlIHJldG9ybmEgdG9kb3Mgb3MgdXN1w6FyaW9zXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAR2V0KClcbiAgYXN5bmMgZ2V0VXNlcnMoKTogUHJvbWlzZTxVc2VyUmVzcG9uc2VEdG8+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5nZXRVc2VycygpO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIHJldG9ybmEgb3MgdXN1w6FyaW9zIGRlIGZvcm1hIHBhZ2luYWRhLCBwb3NzaWJpbGl0YW5kbyBpbnNlcmlyIGZpbHRyb3MgbmEgYnVzY2FcbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBQb3N0KCdieUZpbHRlcnMnKVxuICBhc3luYyBnZXRVc2Vyc0J5RmlsdGVycyhcbiAgICBAQm9keSgpIHVzZXJTZWFyY2hCb2R5OiBVc2VyU2VhcmNoQm9keSxcbiAgICBAUGFyYW0oJ2ZpcnN0JykgZmlyc3Q6IG51bWJlcixcbiAgICBAUGFyYW0oJ3NpemUnKSBzaXplOiBudW1iZXIsXG4gICk6IFByb21pc2U8VXNlclJlc3BvbnNlRHRvPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZ2V0VXNlcnMoZmlyc3QsIHNpemUsIHVzZXJTZWFyY2hCb2R5KTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSByZXRvcm5hIHVtIHVzdcOhcmlvIHBlbG8gc2V1IGlkXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAR2V0KCc6aWQnKVxuICBhc3luYyBnZXRVc2VyQnlJZChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZyk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmdldFVzZXJCeUlkKGlkKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIGRlIGNyaWHDp8OjbyBkZSB1bSB1c3XDoXJpb1xuICBAUG9zdCgnLycpXG4gIGFzeW5jIGNyZWF0ZVVzZXIoQEJvZHkoKSBjcmVhdGVVc2VyRHRvOiBDcmVhdGVVc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuY3JlYXRlVXNlcihjcmVhdGVVc2VyRHRvKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIGRlIGF0dWFsaXphw6fDo28gZGUgdW0gdXN1w6FyaW9cbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBQdXQoJzppZCcpXG4gIGFzeW5jIHVwZGF0ZVVzZXIoXG4gICAgQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsXG4gICAgQEJvZHkoKSB1cGRhdGVVc2VyRHRvOiBVcGRhdGVVc2VyRHRvLFxuICApOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS51cGRhdGVVc2VyKGlkLCB1cGRhdGVVc2VyRHRvKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSBwZXJtaXRlIGEgdW0gdXN1w6FyaW8gcmVjdXBlcmFyIG8gc2V1IGFjZXNzbyBhbHRlcmFuZG8gYSBzZW5oYVxuICBAUHV0KCdwYXNzd29yZC9yZWNvdmVyJylcbiAgYXN5bmMgcmVjb3ZlclBhc3N3b3JkKFxuICAgIEBCb2R5KCkgcmVjb3ZlclBhc3N3b3JkRHRvOiBSZWNvdmVyUGFzc3dvcmREdG8sXG4gICk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLnJlY292ZXJQYXNzd29yZChyZWNvdmVyUGFzc3dvcmREdG8pO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIGFsdGVyYSBvIHN0YXR1cyBkZSB1bSB1c3XDoXJpb1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQFB1dCgnOmlkL3N0YXR1cycpXG4gIGFzeW5jIGNoYW5nZVVzZXJTdGF0dXMoXG4gICAgQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsXG4gICAgQEJvZHkoKSB7IHN0YXR1cyB9OiB7IHN0YXR1czogVXNlclN0YXR1cyB9LFxuICApOiBQcm9taXNlPFVzZXJDaGFuZ2VSZXN1bHQ+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5jaGFuZ2VVc2VyU3RhdHVzKGlkLCBzdGF0dXMpO1xuICB9XG5cbiAgLy8gU2VydmnDp28gcXVlIGluYXRpdmEgdG9kb3Mgb3MgdXN1w6FyaW9zXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBARGVsZXRlKCdpbmFjdGl2ZScpXG4gIGFzeW5jIGluYWN0aXZlVXNlckJ1bGsoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuaW5hY3RpdmVVc2VyQnVsaygpO1xuICB9XG59XG4iLCJpbXBvcnQgeyBmb3J3YXJkUmVmLCBHbG9iYWwsIE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nO1xuaW1wb3J0IHsgVXNlciB9IGZyb20gJy4vZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclJlcG9zaXRvcnkgfSBmcm9tICcuL3JlcG9zaXRvcmllcy91c2VyLnJlcG9zaXRvcnknO1xuaW1wb3J0IHsgVXNlckNvbnRyb2xsZXIgfSBmcm9tICcuL3VzZXIuY29udHJvbGxlcic7XG5pbXBvcnQgeyBVc2VyU2VydmljZSB9IGZyb20gJy4vdXNlci5zZXJ2aWNlJztcbmltcG9ydCB7IEVsYXN0aWNTZWFyY2hNb2R1bGUgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoL2VsYXN0aWMtc2VhcmNoLm1vZHVsZSc7XG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZyc7XG5pbXBvcnQgeyBBdXRoTW9kdWxlIH0gZnJvbSAnYXBwcy9hdXRoL3NyYy9hdXRoLm1vZHVsZSc7XG5cbkBHbG9iYWwoKVxuQE1vZHVsZSh7XG4gIGltcG9ydHM6IFtcbiAgICBDb25maWdNb2R1bGUuZm9yUm9vdCh7IGlzR2xvYmFsOiB0cnVlIH0pLFxuICAgIFR5cGVPcm1Nb2R1bGUuZm9yUm9vdCh7XG4gICAgICB0eXBlOiAnbXlzcWwnLFxuICAgICAgaG9zdDogJ215c3FsX3VzZXInLFxuICAgICAgZGF0YWJhc2U6ICd1c2VycycsXG4gICAgICBwb3J0OiAzMzA2LFxuICAgICAgdXNlcm5hbWU6ICdyb290JyxcbiAgICAgIHBhc3N3b3JkOiAncm9vdCcsXG4gICAgICBlbnRpdGllczogW1VzZXJdLFxuICAgICAgc3luY2hyb25pemU6IHRydWUsXG4gICAgICBhdXRvTG9hZEVudGl0aWVzOiB0cnVlLFxuICAgICAgZHJvcFNjaGVtYTogZmFsc2UsXG4gICAgICBtaWdyYXRpb25zUnVuOiBmYWxzZSxcbiAgICAgIGxvZ2dpbmc6IFsnd2FybicsICdlcnJvciddLFxuICAgICAgY2xpOiB7XG4gICAgICAgIG1pZ3JhdGlvbnNEaXI6ICdhcHBzL3VzZXIvc3JjL21pZ3JhdGlvbnMnLFxuICAgICAgfSxcbiAgICB9KSxcbiAgICBUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW1VzZXJSZXBvc2l0b3J5XSksXG4gICAgRWxhc3RpY1NlYXJjaE1vZHVsZSxcbiAgICBmb3J3YXJkUmVmKCgpID0+IEF1dGhNb2R1bGUpLFxuICBdLFxuICBwcm92aWRlcnM6IFtVc2VyU2VydmljZV0sXG4gIGNvbnRyb2xsZXJzOiBbVXNlckNvbnRyb2xsZXJdLFxuICBleHBvcnRzOiBbVXNlclNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBVc2VyTW9kdWxlIHt9XG4iLCJpbXBvcnQge1xuICBGb3JiaWRkZW5FeGNlcHRpb24sXG4gIEluamVjdGFibGUsXG4gIEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24sXG4gIE5vdEZvdW5kRXhjZXB0aW9uLFxufSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBEZWxldGVSZXN1bHQgfSBmcm9tICd0eXBlb3JtJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBSZWNvdmVyUGFzc3dvcmREdG8gfSBmcm9tICcuL2R0by9yZWNvdmVyUGFzc3dvcmQuZHRvJztcbmltcG9ydCB7IFVwZGF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyQ2hhbmdlUmVzdWx0IH0gZnJvbSAnLi9kdG8vdXNlckNoYW5nZVJlc3VsdC5kdG8nO1xuaW1wb3J0IHsgVXNlclJlc3BvbnNlRHRvIH0gZnJvbSAnLi9kdG8vdXNlclJlc3BvbnNlLmR0byc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoU2VydmljZSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2guc2VydmljZSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclJlcG9zaXRvcnkgfSBmcm9tICcuL3JlcG9zaXRvcmllcy91c2VyLnJlcG9zaXRvcnknO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVXNlclNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwcml2YXRlIHVzZXJSZXBvc2l0b3J5OiBVc2VyUmVwb3NpdG9yeSxcbiAgICBwcml2YXRlIGVsYXN0aWNTZWFyY2hTZXJ2aWNlOiBFbGFzdGljU2VhcmNoU2VydmljZSxcbiAgKSB7fVxuXG4gIGFzeW5jIGdldFVzZXJzKFxuICAgIGZpcnN0ID0gMCxcbiAgICBzaXplID0gMCxcbiAgICB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHkgPSBudWxsLFxuICApOiBQcm9taXNlPFVzZXJSZXNwb25zZUR0bz4ge1xuICAgIGlmICh1c2VyU2VhcmNoQm9keSkge1xuICAgICAgY29uc3QgeyBiaXJ0aERhdGUsIGNyZWF0ZWRBdCwgdXBkYXRlZEF0IH0gPSB1c2VyU2VhcmNoQm9keTtcblxuICAgICAgaWYgKGJpcnRoRGF0ZSB8fCBjcmVhdGVkQXQgfHwgdXBkYXRlZEF0IHx8IHRydWUpIHtcbiAgICAgICAgY29uc3QgdXNlcnMgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRCeUZpbHRlcnMoXG4gICAgICAgICAgdXNlclNlYXJjaEJvZHksXG4gICAgICAgICAgZmlyc3QsXG4gICAgICAgICAgc2l6ZSxcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgY291bnQgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5KTtcblxuICAgICAgICBjb25zdCB1c2VyUmVzcG9uc2VEdG8gPSBuZXcgVXNlclJlc3BvbnNlRHRvKHVzZXJzLCBjb3VudCk7XG5cbiAgICAgICAgcmV0dXJuIHVzZXJSZXNwb25zZUR0bztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxldCB1c2VyU2VhcmNoQm9keUxpc3Q6IFVzZXJTZWFyY2hCb2R5W10gPSBbXTtcblxuICAgICAgICBsZXQgaW5kZXggPSAxO1xuXG4gICAgICAgIGZvciAoY29uc3QgW2F0dHJpYnV0ZU5hbWUsIGF0dHJpYnV0ZVZhbHVlXSBvZiBPYmplY3QuZW50cmllcyhcbiAgICAgICAgICB1c2VyU2VhcmNoQm9keSxcbiAgICAgICAgKSkge1xuICAgICAgICAgIGlmIChhdHRyaWJ1dGVWYWx1ZSkge1xuICAgICAgICAgICAgY29uc3QgcGFydGlhbFNlYXJjaCA9IGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2Uuc2VhcmNoKFxuICAgICAgICAgICAgICBmaXJzdCxcbiAgICAgICAgICAgICAgc2l6ZSxcbiAgICAgICAgICAgICAgYXR0cmlidXRlVmFsdWUsXG4gICAgICAgICAgICAgIFthdHRyaWJ1dGVOYW1lXSxcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QgPVxuICAgICAgICAgICAgICBpbmRleCA+IDFcbiAgICAgICAgICAgICAgICA/IHBhcnRpYWxTZWFyY2guZmlsdGVyKChpdGVtKSA9PlxuICAgICAgICAgICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QuaW5jbHVkZXMoaXRlbSksXG4gICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgOiBbLi4ucGFydGlhbFNlYXJjaF07XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHVzZXJSZXNwb25zZUR0byA9IG5ldyBVc2VyUmVzcG9uc2VEdG8oXG4gICAgICAgICAgdXNlclNlYXJjaEJvZHlMaXN0LFxuICAgICAgICAgIHVzZXJTZWFyY2hCb2R5TGlzdC5sZW5ndGgsXG4gICAgICAgICk7XG5cbiAgICAgICAgcmV0dXJuIHVzZXJSZXNwb25zZUR0bztcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gUmV0b3JuYSB0b2RvcyBvcyB1c3XDoXJpb3Mgbm8gZWxhc3RpYyBzZWFyY2ggY29tIG8gc3RhdHVzIGF0aXZvXG4gICAgICAvLyBjb25zdCB1c2VycyA9IGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2Uuc2VhcmNoKFxuICAgICAgLy8gICBmaXJzdCxcbiAgICAgIC8vICAgc2l6ZSxcbiAgICAgIC8vICAgVXNlclN0YXR1cy5BY3RpdmUsXG4gICAgICAvLyAgIFsnc3RhdHVzJ10sXG4gICAgICAvLyApO1xuXG4gICAgICAvLyBjb25zdCB7IGNvdW50IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNTZWFyY2hTZXJ2aWNlLmNvdW50KFxuICAgICAgLy8gICBVc2VyU3RhdHVzLkFjdGl2ZSxcbiAgICAgIC8vICAgWydzdGF0dXMnXSxcbiAgICAgIC8vICk7XG4gICAgICAvLyBjb25zdCB1c2VyUmVzcG9uc2VEdG8gPSBuZXcgVXNlclJlc3BvbnNlRHRvKHVzZXJzLCBjb3VudCk7XG4gICAgICAvLyByZXR1cm4gdXNlclJlc3BvbnNlRHRvO1xuXG4gICAgICAvLyBSZXRvcm5hIHRvZG9zIG9zIHVzdcOhcmlvcyBjb20gbyBzdGF0dXMgYXRpdm8sIGRlIGZvcm1hIHBhZ2luYWRhXG4gICAgICBjb25zdCB1c2VycyA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZEJ5RmlsdGVycyhcbiAgICAgICAgdXNlclNlYXJjaEJvZHksXG4gICAgICAgIGZpcnN0LFxuICAgICAgICBzaXplLFxuICAgICAgKTtcbiAgICAgIGNvbnN0IGNvdW50ID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5jb3VudEJ5RmlsdGVycyh1c2VyU2VhcmNoQm9keSk7XG5cbiAgICAgIGNvbnN0IHVzZXJSZXNwb25zZUR0byA9IG5ldyBVc2VyUmVzcG9uc2VEdG8odXNlcnMsIGNvdW50KTtcblxuICAgICAgcmV0dXJuIHVzZXJSZXNwb25zZUR0bztcbiAgICB9XG4gIH1cblxuICBhc3luYyBnZXRVc2VyQnlJZChpZDogc3RyaW5nKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZShpZCk7XG5cbiAgICBpZiAoIXVzZXIpIHtcbiAgICAgIHRocm93IG5ldyBOb3RGb3VuZEV4Y2VwdGlvbignTsOjbyBleGlzdGUgdW0gdXN1w6FyaW8gY29tIG8gaWQgcGFzc2FkbycpO1xuICAgIH1cblxuICAgIHJldHVybiB1c2VyO1xuICB9XG5cbiAgYXN5bmMgY3JlYXRlVXNlcihjcmVhdGVVc2VyRHRvOiBDcmVhdGVVc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBjcGYsIGVtYWlsLCBsb2dpbiB9ID0gY3JlYXRlVXNlckR0bztcblxuICAgIGNvbnN0IHVzZXJBbHJlYWR5RXhpc3QgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LnVzZXJBbHJlYWR5RXhpc3QoXG4gICAgICBjcGYsXG4gICAgICBlbWFpbCxcbiAgICAgIGxvZ2luLFxuICAgICk7XG5cbiAgICBpZiAodXNlckFscmVhZHlFeGlzdCAmJiB1c2VyQWxyZWFkeUV4aXN0Lmxlbmd0aCkge1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oXG4gICAgICAgIGBKw6EgZXhpc3RlIHVtIHVzdcOhcmlvIGNhZGFzdHJhZG8gY29tIG8gY3BmLCBlbWFpbCBvdSBsb2dpbiBwYXNzYWRvc2AsXG4gICAgICApO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNyZWF0ZUFuZFNhdmUoY3JlYXRlVXNlckR0byk7XG5cbiAgICAgIGNvbnN0IGNyZWF0ZWRVc2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKHtcbiAgICAgICAgd2hlcmU6IHsgbG9naW4gfSxcbiAgICAgIH0pO1xuXG4gICAgICB0aGlzLmVsYXN0aWNTZWFyY2hTZXJ2aWNlLmluZGV4KGNyZWF0ZWRVc2VyKTtcblxuICAgICAgcmV0dXJuIGNyZWF0ZWRVc2VyO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oZXJyLnNxbE1lc3NhZ2UgfHwgZXJyKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyB1cGRhdGVVc2VyKGlkOiBzdHJpbmcsIHVwZGF0ZVVzZXJEdG86IFVwZGF0ZVVzZXJEdG8pOiBQcm9taXNlPFVzZXI+IHtcbiAgICBjb25zdCB7IGNwZiwgZW1haWwsIGxvZ2luIH0gPSB1cGRhdGVVc2VyRHRvO1xuXG4gICAgY29uc3QgdXNlckFscmVhZHlFeGlzdCA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkudXNlckFscmVhZHlFeGlzdChcbiAgICAgIGNwZixcbiAgICAgIGVtYWlsLFxuICAgICAgbG9naW4sXG4gICAgKTtcblxuICAgIGlmICh1c2VyQWxyZWFkeUV4aXN0ICYmIHVzZXJBbHJlYWR5RXhpc3QubGVuZ3RoKSB7XG4gICAgICBjb25zdCByZWFsbHlBbm90aGVyVXNlciA9IHVzZXJBbHJlYWR5RXhpc3QuZmluZCgodXNlcikgPT4gdXNlci5pZCAhPT0gaWQpO1xuXG4gICAgICBpZiAocmVhbGx5QW5vdGhlclVzZXIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oXG4gICAgICAgICAgYErDoSBleGlzdGUgdW0gdXN1w6FyaW8gY2FkYXN0cmFkbyBjb20gbyBjcGYsIGVtYWlsIG91IGxvZ2luIHBhc3NhZG9zYCxcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKGlkKTtcblxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LnVwZGF0ZUFuZFNhdmUodXNlciwgdXBkYXRlVXNlckR0byk7XG5cbiAgICAgIGNvbnN0IHVwZGF0ZWRVc2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKHtcbiAgICAgICAgd2hlcmU6IHsgbG9naW4gfSxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBhd2FpdCB0aGlzLmVsYXN0aWNTZWFyY2hTZXJ2aWNlLnVwZGF0ZSh1cGRhdGVkVXNlcik7XG5cbiAgICAgIHJldHVybiB1cGRhdGVkVXNlcjtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgcmVjb3ZlclBhc3N3b3JkKHJlY292ZXJQYXNzd29yZER0bzogUmVjb3ZlclBhc3N3b3JkRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBjcGYsIGVtYWlsLCBuYW1lLCBuZXdQYXNzd29yZCB9ID0gcmVjb3ZlclBhc3N3b3JkRHRvO1xuXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICB3aGVyZToge1xuICAgICAgICBjcGYsXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgaWYgKCF1c2VyIHx8IHVzZXIuZW1haWwgIT09IGVtYWlsIHx8IHVzZXIubmFtZSAhPT0gbmFtZSkge1xuICAgICAgdGhyb3cgbmV3IEZvcmJpZGRlbkV4Y2VwdGlvbignQXMgaW5mb3JtYcOnw7VlcyBwYXNzYWRhcyBlc3TDo28gaW5jb3JyZXRhcycpO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNoYW5nZVBhc3N3b3JkQW5kU2F2ZSh1c2VyLCBuZXdQYXNzd29yZCk7XG5cbiAgICAgIHJldHVybiB1c2VyO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oZXJyLnNxbE1lc3NhZ2UgfHwgZXJyKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBmaW5kQnlMb2dpbihsb2dpbjogc3RyaW5nKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICB3aGVyZToge1xuICAgICAgICBsb2dpbixcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBjaGFuZ2VVc2VyU3RhdHVzKFxuICAgIGlkOiBzdHJpbmcsXG4gICAgdXNlclN0YXR1czogVXNlclN0YXR1cyxcbiAgKTogUHJvbWlzZTxVc2VyQ2hhbmdlUmVzdWx0PiB7XG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZShpZCk7XG5cbiAgICBpZiAoIXVzZXIpIHtcbiAgICAgIHRocm93IG5ldyBOb3RGb3VuZEV4Y2VwdGlvbignVXN1w6FyaW8gbsOjbyBleGlzdGUnKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgdXBkYXRlVXNlckR0byA9IG5ldyBVcGRhdGVVc2VyRHRvKCk7XG4gICAgICB1cGRhdGVVc2VyRHRvLnN0YXR1cyA9IHVzZXJTdGF0dXM7XG5cbiAgICAgIGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkudXBkYXRlQW5kU2F2ZSh1c2VyLCB1cGRhdGVVc2VyRHRvKTtcblxuICAgICAgY29uc3QgdXNlckNoYW5nZVJlc3VsdDogVXNlckNoYW5nZVJlc3VsdCA9IHtcbiAgICAgICAgYWZmZWN0ZWQ6IDEsXG4gICAgICB9O1xuXG4gICAgICByZXR1cm4gdXNlckNoYW5nZVJlc3VsdDtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgaW5hY3RpdmVVc2VyQnVsaygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc29sZS5sb2coJ2hlcmUnKTtcbiAgICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmluYWN0aXZlQWxsVXNlcnMoKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUubG9nKGVycik7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvZWxhc3RpY3NlYXJjaFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2p3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Bhc3Nwb3J0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInBhc3Nwb3J0LWp3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJ0eXBlb3JtXCIpOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0uY2FsbChtb2R1bGUuZXhwb3J0cywgbW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCJpbXBvcnQgeyBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IE5lc3RGYWN0b3J5IH0gZnJvbSAnQG5lc3Rqcy9jb3JlJztcbmltcG9ydCB7IFVzZXJNb2R1bGUgfSBmcm9tICcuL3VzZXIubW9kdWxlJztcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuICBjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoVXNlck1vZHVsZSk7XG4gIGFwcC51c2VHbG9iYWxQaXBlcyhuZXcgVmFsaWRhdGlvblBpcGUoKSk7XG4gIGFwcC5lbmFibGVDb3JzKHsgb3JpZ2luOiBbJ2h0dHA6Ly9sb2NhbGhvc3Q6NDIwMCddIH0pO1xuICBhd2FpdCBhcHAubGlzdGVuKDMwMDApO1xufVxuYm9vdHN0cmFwKCk7XG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=