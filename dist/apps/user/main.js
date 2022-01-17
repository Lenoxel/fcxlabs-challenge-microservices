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
    (0, typeorm_1.Column)({ unique: true, type: 'varchar', length: 11 }),
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

/***/ "./apps/user/src/models/age-scale.model.ts":
/*!*************************************************!*\
  !*** ./apps/user/src/models/age-scale.model.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AgeScaleClass = void 0;
class AgeScaleClass {
    constructor(ageScaleType) {
        this.start = '';
        this.end = '';
        this.setDates(ageScaleType);
    }
    getStart() {
        return this.start;
    }
    getEnd() {
        return this.end;
    }
    setDates(ageScaleType) {
        const startDate = new Date();
        const endDate = new Date();
        const rangeDate = {
            Between18And26: () => {
                startDate.setFullYear(startDate.getFullYear() - 26);
                endDate.setFullYear(endDate.getFullYear() - 18);
                this.start = startDate.toISOString();
                this.end = endDate.toISOString();
            },
            Between25And31: () => {
                startDate.setFullYear(startDate.getFullYear() - 31);
                endDate.setFullYear(endDate.getFullYear() - 25);
                this.start = startDate.toISOString();
                this.end = endDate.toISOString();
            },
            Between30And36: () => {
                startDate.setFullYear(startDate.getFullYear() - 36);
                endDate.setFullYear(endDate.getFullYear() - 30);
                this.start = startDate.toISOString();
                this.end = endDate.toISOString();
            },
            Between35And41: () => {
                startDate.setFullYear(startDate.getFullYear() - 41);
                endDate.setFullYear(endDate.getFullYear() - 35);
                this.start = startDate.toISOString();
                this.end = endDate.toISOString();
            },
            GreaterThan40: () => {
                endDate.setFullYear(endDate.getFullYear() - 40);
                this.end = endDate.toISOString();
            },
        };
        rangeDate[ageScaleType].call();
    }
}
exports.AgeScaleClass = AgeScaleClass;


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
const age_scale_model_1 = __webpack_require__(/*! ../models/age-scale.model */ "./apps/user/src/models/age-scale.model.ts");
const date_fns_1 = __webpack_require__(/*! date-fns */ "date-fns");
let UserRepository = class UserRepository extends typeorm_1.Repository {
    async findByFilters(userSearchBody, first = 0, size = 0) {
        if (userSearchBody) {
            const { name, login, cpf, status, ageScale, createdAt, updatedAt } = userSearchBody;
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
            if (ageScale) {
                const ageScaleClass = new age_scale_model_1.AgeScaleClass(ageScale);
                if (firstWhere) {
                    if (ageScaleClass.getStart()) {
                        queryBuilder.where('user.birthDate BETWEEN :start AND :end', {
                            start: ageScaleClass.getStart(),
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    else {
                        queryBuilder.where('user.birthDate < :end', {
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    firstWhere = false;
                }
                else {
                    if (ageScaleClass.getStart()) {
                        queryBuilder.andWhere('user.birthDate BETWEEN :start AND :end', {
                            start: ageScaleClass.getStart(),
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    else {
                        queryBuilder.andWhere('user.birthDate < :end', {
                            end: ageScaleClass.getEnd(),
                        });
                    }
                }
            }
            if (createdAt) {
                if (createdAt.start) {
                    if (firstWhere) {
                        queryBuilder.where('user.createdAt >= :createdAtStartDate', {
                            createdAtStartDate: (0, date_fns_1.startOfDay)(createdAt.start).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.createdAt >= :createdAtStartDate', {
                            createdAtStartDate: (0, date_fns_1.startOfDay)(createdAt.start).toISOString(),
                        });
                    }
                }
                if (createdAt.end) {
                    if (firstWhere) {
                        queryBuilder.where('user.createdAt <= :createdAtEndDate', {
                            createdAtEndDate: (0, date_fns_1.endOfDay)(createdAt.end).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.createdAt <= :createdAtEndDate', {
                            createdAtEndDate: (0, date_fns_1.endOfDay)(createdAt.end).toISOString(),
                        });
                    }
                }
            }
            if (updatedAt) {
                if (updatedAt.start) {
                    if (firstWhere) {
                        queryBuilder.where('user.updatedAt >= :updatedAtStartDate', {
                            updatedAtStartDate: (0, date_fns_1.startOfDay)(updatedAt.start).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.updatedAt >= :updatedAtStartDate', {
                            updatedAtStartDate: (0, date_fns_1.startOfDay)(updatedAt.start).toISOString(),
                        });
                    }
                }
                if (updatedAt.end) {
                    if (firstWhere) {
                        queryBuilder.where('user.updatedAt <= :updatedAtEndDate', {
                            updatedAtEndDate: (0, date_fns_1.endOfDay)(updatedAt.end).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.updatedAt <= :updatedAtEndDate', {
                            updatedAtEndDate: (0, date_fns_1.endOfDay)(updatedAt.end).toISOString(),
                        });
                    }
                }
            }
            if (size > 0) {
                queryBuilder.skip(first).take(size);
            }
            return await queryBuilder.getMany();
        }
        else {
            const queryBuilder = this.createQueryBuilder('user').where('user.status != :status', {
                status: user_status_enum_1.UserStatus.Inactive,
            });
            if (size > 0) {
                queryBuilder.skip(first).take(size);
            }
            return await queryBuilder.getMany();
        }
    }
    async countByFilters(userSearchBody) {
        if (userSearchBody) {
            const { name, login, cpf, status, ageScale, createdAt, updatedAt } = userSearchBody;
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
            if (ageScale) {
                const ageScaleClass = new age_scale_model_1.AgeScaleClass(ageScale);
                if (firstWhere) {
                    if (ageScaleClass.getStart()) {
                        queryBuilder.where('user.birthDate BETWEEN :start AND :end', {
                            start: ageScaleClass.getStart(),
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    else {
                        queryBuilder.where('user.birthDate < :end', {
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    firstWhere = false;
                }
                else {
                    if (ageScaleClass.getStart()) {
                        queryBuilder.andWhere('user.birthDate BETWEEN :start AND :end', {
                            start: ageScaleClass.getStart(),
                            end: ageScaleClass.getEnd(),
                        });
                    }
                    else {
                        queryBuilder.andWhere('user.birthDate < :end', {
                            end: ageScaleClass.getEnd(),
                        });
                    }
                }
            }
            if (createdAt) {
                if (createdAt.start) {
                    if (firstWhere) {
                        queryBuilder.where('user.createdAt >= :createdAtStartDate', {
                            createdAtStartDate: (0, date_fns_1.startOfDay)(createdAt.start).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.createdAt >= :createdAtStartDate', {
                            createdAtStartDate: (0, date_fns_1.startOfDay)(createdAt.start).toISOString(),
                        });
                    }
                }
                if (createdAt.end) {
                    if (firstWhere) {
                        queryBuilder.where('user.createdAt <= :createdAtEndDate', {
                            createdAtEndDate: (0, date_fns_1.endOfDay)(createdAt.end).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.createdAt <= :createdAtEndDate', {
                            createdAtEndDate: (0, date_fns_1.endOfDay)(createdAt.end).toISOString(),
                        });
                    }
                }
            }
            if (updatedAt) {
                if (updatedAt.start) {
                    if (firstWhere) {
                        queryBuilder.where('user.updatedAt >= :updatedAtStartDate', {
                            updatedAtStartDate: (0, date_fns_1.startOfDay)(updatedAt.start).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.updatedAt >= :updatedAtStartDate', {
                            updatedAtStartDate: (0, date_fns_1.startOfDay)(updatedAt.start).toISOString(),
                        });
                    }
                }
                if (updatedAt.end) {
                    if (firstWhere) {
                        queryBuilder.where('user.updatedAt <= :updatedAtEndDate', {
                            updatedAtEndDate: (0, date_fns_1.endOfDay)(updatedAt.end).toISOString(),
                        });
                        firstWhere = false;
                    }
                    else {
                        queryBuilder.andWhere('user.updatedAt <= :updatedAtEndDate', {
                            updatedAtEndDate: (0, date_fns_1.endOfDay)(updatedAt.end).toISOString(),
                        });
                    }
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
    __param(1, (0, common_1.Query)('first')),
    __param(2, (0, common_1.Query)('size')),
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
                synchronize: false,
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
            const { ageScale, createdAt, updatedAt } = userSearchBody;
            if (ageScale || createdAt || updatedAt || true) {
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

/***/ "date-fns":
/*!***************************!*\
  !*** external "date-fns" ***!
  \***************************/
/***/ ((module) => {

module.exports = require("date-fns");

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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Ozs7QUN0QkEsNkVBQWdEO0FBQ2hELHVFQUEyQztBQUMzQyxpR0FBMkM7QUFFM0MsS0FBSyxVQUFVLFNBQVM7SUFDdEIsTUFBTSxHQUFHLEdBQUcsTUFBTSxrQkFBVyxDQUFDLE1BQU0sQ0FBQyx3QkFBVSxDQUFDLENBQUM7SUFDakQsR0FBRyxDQUFDLGNBQWMsQ0FBQyxJQUFJLHVCQUFjLEVBQUUsQ0FBQyxDQUFDO0lBQ3pDLEdBQUcsQ0FBQyxVQUFVLENBQUMsRUFBRSxNQUFNLEVBQUUsQ0FBQyx1QkFBdUIsQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0RCxNQUFNLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDekIsQ0FBQztBQUNELFNBQVMsRUFBRSxDQUFDIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGguY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvYXV0aC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGguc2VydmljZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvand0L2p3dC1hdXRoLmd1YXJkLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9qd3Qvand0LnN0cmF0ZWd5LnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vY3JlYXRlVXNlci5kdG8udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vcmVjb3ZlclBhc3N3b3JkLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL3VwZGF0ZVVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vdXNlclJlc3BvbnNlLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2gubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5zZXJ2aWNlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbnRpdGllcy91c2VyLmVudGl0eS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZW51bXMvdXNlci1zdGF0dXMuZW51bS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvbW9kZWxzL2FnZS1zY2FsZS5tb2RlbC50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvcmVwb3NpdG9yaWVzL3VzZXIucmVwb3NpdG9yeS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvdXNlci5jb250cm9sbGVyLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy91c2VyLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvdXNlci5zZXJ2aWNlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb25cIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29uZmlnXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvcmVcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvZWxhc3RpY3NlYXJjaFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9qd3RcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvcGFzc3BvcnRcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiYmNyeXB0XCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJjbGFzcy12YWxpZGF0b3JcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcImRhdGUtZm5zXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJwYXNzcG9ydC1qd3RcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcInR5cGVvcm1cIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvbWFpbi50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBQb3N0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgTG9naW5Vc2VyRHRvIH0gZnJvbSAnYXBwcy91c2VyL3NyYy9kdG8vbG9naW5Vc2VyLmR0byc7XG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJztcblxuQENvbnRyb2xsZXIoJ2FwaS92MS9hdXRoJylcbmV4cG9ydCBjbGFzcyBBdXRoQ29udHJvbGxlciB7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgYXV0aFNlcnZpY2U6IEF1dGhTZXJ2aWNlKSB7fVxuXG4gIEBQb3N0KCdsb2dpbicpXG4gIGFzeW5jIGxvZ2luKFxuICAgIEBCb2R5KCkgbG9naW5Vc2VyRHRvOiBMb2dpblVzZXJEdG8sXG4gICk6IFByb21pc2U8eyBhY2Nlc3NUb2tlbjogc3RyaW5nIH0+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5sb2dpbihsb2dpblVzZXJEdG8pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBmb3J3YXJkUmVmLCBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1NlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2NvbmZpZyc7XG5pbXBvcnQgeyBKd3RNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2p3dCc7XG5pbXBvcnQgeyBQYXNzcG9ydE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvcGFzc3BvcnQnO1xuaW1wb3J0IHsgVXNlck1vZHVsZSB9IGZyb20gJ2FwcHMvdXNlci9zcmMvdXNlci5tb2R1bGUnO1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcic7XG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJztcbmltcG9ydCB7IEp3dFN0cmF0ZWd5IH0gZnJvbSAnLi9qd3Qvand0LnN0cmF0ZWd5JztcblxuQE1vZHVsZSh7XG4gIGltcG9ydHM6IFtcbiAgICBDb25maWdNb2R1bGUuZm9yUm9vdCh7IGlzR2xvYmFsOiB0cnVlIH0pLFxuICAgIFBhc3Nwb3J0TW9kdWxlLFxuICAgIEp3dE1vZHVsZS5yZWdpc3RlckFzeW5jKHtcbiAgICAgIGltcG9ydHM6IFtDb25maWdNb2R1bGVdLFxuICAgICAgdXNlRmFjdG9yeTogYXN5bmMgKCkgPT4gKHtcbiAgICAgICAgc2VjcmV0OiBwcm9jZXNzLmVudi5KV1RfU0VDUkVULFxuICAgICAgfSksXG4gICAgICBpbmplY3Q6IFtDb25maWdTZXJ2aWNlXSxcbiAgICB9KSxcbiAgICBmb3J3YXJkUmVmKCgpID0+IFVzZXJNb2R1bGUpLFxuICBdLFxuICBjb250cm9sbGVyczogW0F1dGhDb250cm9sbGVyXSxcbiAgcHJvdmlkZXJzOiBbQXV0aFNlcnZpY2UsIEp3dFN0cmF0ZWd5XSxcbiAgZXhwb3J0czogW0F1dGhTZXJ2aWNlLCBKd3RTdHJhdGVneV0sXG59KVxuZXhwb3J0IGNsYXNzIEF1dGhNb2R1bGUge31cbiIsImltcG9ydCB7XG4gIEluamVjdGFibGUsXG4gIE5vdEZvdW5kRXhjZXB0aW9uLFxuICBVbmF1dGhvcml6ZWRFeGNlcHRpb24sXG59IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEp3dFNlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2p3dCc7XG5pbXBvcnQgeyBMb2dpblVzZXJEdG8gfSBmcm9tICdhcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICdhcHBzL3VzZXIvc3JjL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICdhcHBzL3VzZXIvc3JjL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICdhcHBzL3VzZXIvc3JjL3VzZXIuc2VydmljZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdXRoU2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHByaXZhdGUgdXNlclNlcnZpY2U6IFVzZXJTZXJ2aWNlLFxuICAgIHByaXZhdGUgand0U2VydmljZTogSnd0U2VydmljZSxcbiAgKSB7fVxuXG4gIGFzeW5jIGxvZ2luKGxvZ2luVXNlckR0bzogTG9naW5Vc2VyRHRvKTogUHJvbWlzZTx7IGFjY2Vzc1Rva2VuOiBzdHJpbmcgfT4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnZhbGlkYXRlVXNlcihsb2dpblVzZXJEdG8pO1xuXG4gICAgY29uc3QgcGF5bG9hZCA9IHtcbiAgICAgIHVzZXJJZDogdXNlci5pZCxcbiAgICB9O1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGFjY2Vzc1Rva2VuOiB0aGlzLmp3dFNlcnZpY2Uuc2lnbihwYXlsb2FkKSxcbiAgICB9O1xuICB9XG5cbiAgYXN5bmMgdmFsaWRhdGVVc2VyKGxvZ2luVXNlckR0bzogTG9naW5Vc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBsb2dpbiwgcGFzc3dvcmQgfSA9IGxvZ2luVXNlckR0bztcblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmZpbmRCeUxvZ2luKGxvZ2luKTtcblxuICAgIGlmICghdXNlcikge1xuICAgICAgdGhyb3cgbmV3IE5vdEZvdW5kRXhjZXB0aW9uKCdVc3XDoXJpbyBuw6NvIGVuY29udHJhZG8nKTtcbiAgICB9XG5cbiAgICBpZiAodXNlci5zdGF0dXMgIT09IFVzZXJTdGF0dXMuQWN0aXZlKSB7XG4gICAgICB0aHJvdyBuZXcgVW5hdXRob3JpemVkRXhjZXB0aW9uKFxuICAgICAgICBgRXNzZSB1c3XDoXJpbyBlc3TDoSBjb20gbyBzdGF0dXMgJHt1c2VyLnN0YXR1cy52YWx1ZU9mKCl9YCxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgY29uc3QgdmFsaWRhdGVQYXNzd29yZCA9IGF3YWl0IHVzZXIudmFsaWRhdGVQYXNzd29yZChwYXNzd29yZCk7XG5cbiAgICBpZiAoIXZhbGlkYXRlUGFzc3dvcmQpIHtcbiAgICAgIHRocm93IG5ldyBVbmF1dGhvcml6ZWRFeGNlcHRpb24oJ0xvZ2luIG91IHNlbmhhIGluY29ycmV0b3MnKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdXNlcjtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEF1dGhHdWFyZCB9IGZyb20gJ0BuZXN0anMvcGFzc3BvcnQnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSnd0QXV0aEd1YXJkIGV4dGVuZHMgQXV0aEd1YXJkKCdqd3QnKSB7fVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IFBhc3Nwb3J0U3RyYXRlZ3kgfSBmcm9tICdAbmVzdGpzL3Bhc3Nwb3J0JztcbmltcG9ydCB7IEV4dHJhY3RKd3QsIFN0cmF0ZWd5IH0gZnJvbSAncGFzc3BvcnQtand0JztcbmltcG9ydCB7IEp3dFBheWxvYWQgfSBmcm9tICcuL2p3dC5wYXlsb2FkJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEp3dFN0cmF0ZWd5IGV4dGVuZHMgUGFzc3BvcnRTdHJhdGVneShTdHJhdGVneSkge1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICBzdXBlcih7XG4gICAgICBqd3RGcm9tUmVxdWVzdDogRXh0cmFjdEp3dC5mcm9tQXV0aEhlYWRlckFzQmVhcmVyVG9rZW4oKSxcbiAgICAgIGlnbm9yZUV4cGlyYXRpb246IGZhbHNlLFxuICAgICAgc2VjcmV0T3JLZXk6IHByb2Nlc3MuZW52LkpXVF9TRUNSRVQsXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZShwYXlsb2FkOiBKd3RQYXlsb2FkKTogUHJvbWlzZTxhbnk+IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXNlcklkOiBwYXlsb2FkLnVzZXJJZCxcbiAgICB9O1xuICB9XG59XG4iLCJpbXBvcnQge1xuICBJc0VtYWlsLFxuICBJc0VudW0sXG4gIElzTm90RW1wdHksXG4gIElzT3B0aW9uYWwsXG4gIElzUGhvbmVOdW1iZXIsXG4gIElzU3RyaW5nLFxufSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlVXNlckR0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbmFtZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbG9naW46IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNFbWFpbCgpXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNQaG9uZU51bWJlcigpXG4gIHBob25lTnVtYmVyOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBjcGY6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIGJpcnRoRGF0ZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbW90aGVyTmFtZTogc3RyaW5nO1xuXG4gIEBJc09wdGlvbmFsKClcbiAgQElzRW51bShVc2VyU3RhdHVzKVxuICBzdGF0dXM6IFVzZXJTdGF0dXM7XG59XG4iLCJpbXBvcnQgeyBJc05vdEVtcHR5IH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJztcblxuZXhwb3J0IGNsYXNzIExvZ2luVXNlckR0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgbG9naW46IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG59XG4iLCJpbXBvcnQge1xuICBJc0VtYWlsLFxuICBJc0VudW0sXG4gIElzTm90RW1wdHksXG4gIElzT3B0aW9uYWwsXG4gIElzUGhvbmVOdW1iZXIsXG4gIElzU3RyaW5nLFxufSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuZXhwb3J0IGNsYXNzIFJlY292ZXJQYXNzd29yZER0byB7XG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbmFtZTogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzRW1haWwoKVxuICBlbWFpbDogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgY3BmOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBuZXdQYXNzd29yZDogc3RyaW5nO1xufVxuIiwiaW1wb3J0IHsgSXNTdHJpbmcgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InO1xuaW1wb3J0IHsgQ3JlYXRlVXNlckR0byB9IGZyb20gJy4vY3JlYXRlVXNlci5kdG8nO1xuXG5leHBvcnQgY2xhc3MgVXBkYXRlVXNlckR0byBleHRlbmRzIENyZWF0ZVVzZXJEdG8ge1xuICBASXNTdHJpbmcoKVxuICBwYXNzd29yZDogc3RyaW5nO1xufVxuIiwiaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuLi9lbGFzdGljLXNlYXJjaC9pbnRlcmZhY2VzL3VzZXJTZWFyY2hCb2R5LnR5cGUnO1xuaW1wb3J0IHsgVXNlciB9IGZyb20gJy4uL2VudGl0aWVzL3VzZXIuZW50aXR5JztcblxuZXhwb3J0IGNsYXNzIFVzZXJSZXNwb25zZUR0byB7XG4gIGRhdGE6IFVzZXJbXSB8IFVzZXJTZWFyY2hCb2R5W107XG4gIGNvdW50OiBudW1iZXI7XG5cbiAgcHVibGljIGNvbnN0cnVjdG9yKGRhdGE6IFVzZXJbXSB8IFVzZXJTZWFyY2hCb2R5W10sIGNvdW50OiBudW1iZXIpIHtcbiAgICB0aGlzLmRhdGEgPSBkYXRhO1xuICAgIHRoaXMuY291bnQgPSBjb3VudDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlLCBDb25maWdTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgRWxhc3RpY1NlYXJjaFNlcnZpY2UgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoLnNlcnZpY2UnO1xuaW1wb3J0IHsgRWxhc3RpY3NlYXJjaE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvZWxhc3RpY3NlYXJjaCc7XG5cbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLFxuICAgIEVsYXN0aWNzZWFyY2hNb2R1bGUucmVnaXN0ZXJBc3luYyh7XG4gICAgICBpbXBvcnRzOiBbQ29uZmlnTW9kdWxlXSxcbiAgICAgIHVzZUZhY3Rvcnk6IGFzeW5jIChjb25maWdTZXJ2aWNlOiBDb25maWdTZXJ2aWNlKSA9PiAoe1xuICAgICAgICBub2RlOiBjb25maWdTZXJ2aWNlLmdldCgnRUxBU1RJQ1NFQVJDSF9OT0RFJyksXG4gICAgICAgIGF1dGg6IHtcbiAgICAgICAgICB1c2VybmFtZTogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfVVNFUk5BTUUnKSxcbiAgICAgICAgICBwYXNzd29yZDogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfUEFTU1dPUkQnKSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG4gICAgfSksXG4gIF0sXG4gIHByb3ZpZGVyczogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbiAgZXhwb3J0czogW0VsYXN0aWNTZWFyY2hTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgRWxhc3RpY1NlYXJjaE1vZHVsZSB7fVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEVsYXN0aWNzZWFyY2hTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9lbGFzdGljc2VhcmNoJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyQ291bnRSZXN1bHQgfSBmcm9tICcuL2ludGVyZmFjZXMvdXNlckNvdW50UmVzdWx0LnR5cGUnO1xuaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoUmVzdWx0IH0gZnJvbSAnLi9pbnRlcmZhY2VzL3VzZXJTZWFyY2hSZXN1bHQudHlwZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbGFzdGljU2VhcmNoU2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZWxhc3RpY3NlYXJjaFNlcnZpY2U6IEVsYXN0aWNzZWFyY2hTZXJ2aWNlKSB7fVxuXG4gIGFzeW5jIHNlYXJjaChcbiAgICBmaXJzdDogbnVtYmVyLFxuICAgIHNpemU6IG51bWJlcixcbiAgICB0ZXh0OiBzdHJpbmcsXG4gICAgZmllbGRzOiBzdHJpbmdbXSxcbiAgKTogUHJvbWlzZTxVc2VyU2VhcmNoQm9keVtdPiB7XG4gICAgY29uc3QgeyBib2R5IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLnNlYXJjaDxVc2VyU2VhcmNoUmVzdWx0Pih7XG4gICAgICBpbmRleDogJ3VzZXJzJyxcbiAgICAgIGZyb206IGZpcnN0LFxuICAgICAgc2l6ZSxcbiAgICAgIGJvZHk6IHtcbiAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICBtdWx0aV9tYXRjaDoge1xuICAgICAgICAgICAgcXVlcnk6IHRleHQsXG4gICAgICAgICAgICBmaWVsZHMsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gICAgY29uc3QgaGl0cyA9IGJvZHkuaGl0cy5oaXRzO1xuICAgIHJldHVybiBoaXRzLm1hcCgoaXRlbSkgPT4gaXRlbS5fc291cmNlKTtcbiAgfVxuXG4gIGFzeW5jIGNvdW50KHRleHQ6IHN0cmluZywgZmllbGRzOiBzdHJpbmdbXSk6IFByb21pc2U8VXNlckNvdW50UmVzdWx0PiB7XG4gICAgY29uc3QgeyBib2R5IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmNvdW50PFVzZXJDb3VudFJlc3VsdD4oe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbXVsdGlfbWF0Y2g6IHtcbiAgICAgICAgICAgIHF1ZXJ5OiB0ZXh0LFxuICAgICAgICAgICAgZmllbGRzLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIGJvZHk7XG4gIH1cblxuICBhc3luYyBpbmRleCh7IGlkLCBuYW1lLCBsb2dpbiwgY3BmLCBzdGF0dXMsIGJpcnRoRGF0ZSB9OiBVc2VyKSB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMuZWxhc3RpY3NlYXJjaFNlcnZpY2UuaW5kZXgoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIGlkLFxuICAgICAgICBuYW1lLFxuICAgICAgICBsb2dpbixcbiAgICAgICAgY3BmLFxuICAgICAgICBzdGF0dXMsXG4gICAgICAgIGJpcnRoRGF0ZSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyB1cGRhdGUodXNlcjogVXNlcikge1xuICAgIGF3YWl0IHRoaXMucmVtb3ZlKHVzZXIuaWQpO1xuICAgIGF3YWl0IHRoaXMuaW5kZXgodXNlcik7XG4gIH1cblxuICBhc3luYyByZW1vdmUodXNlcklkOiBzdHJpbmcpIHtcbiAgICB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmRlbGV0ZUJ5UXVlcnkoe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgIGlkOiB1c2VySWQsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cbn1cbiIsImltcG9ydCB7XG4gIEVudGl0eSxcbiAgQ29sdW1uLFxuICBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLFxuICBCZWZvcmVJbnNlcnQsXG4gIFVwZGF0ZURhdGVDb2x1bW4sXG4gIEJlZm9yZVVwZGF0ZSxcbn0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgKiBhcyBiY3J5cHQgZnJvbSAnYmNyeXB0JztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuXG5ARW50aXR5KClcbmV4cG9ydCBjbGFzcyBVc2VyIHtcbiAgQFByaW1hcnlHZW5lcmF0ZWRDb2x1bW4oJ3V1aWQnKVxuICBpZDogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBuYW1lOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIGxvZ2luOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBhc3N3b3JkOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInIH0pXG4gIGVtYWlsOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIHBob25lTnVtYmVyOiBzdHJpbmc7XG5cbiAgQENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgdHlwZTogJ3ZhcmNoYXInLCBsZW5ndGg6IDExIH0pXG4gIGNwZjogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ2RhdGUnKVxuICBiaXJ0aERhdGU6IHN0cmluZztcblxuICBAQ29sdW1uKCd2YXJjaGFyJylcbiAgbW90aGVyTmFtZTogc3RyaW5nO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IFVzZXJTdGF0dXMgfSlcbiAgc3RhdHVzOiBVc2VyU3RhdHVzO1xuXG4gIEBDb2x1bW4oeyB0eXBlOiAndGltZXN0YW1wJywgZGVmYXVsdDogKCkgPT4gJ0NVUlJFTlRfVElNRVNUQU1QJyB9KVxuICBjcmVhdGVkQXQ6IHN0cmluZztcblxuICBAVXBkYXRlRGF0ZUNvbHVtbih7IHR5cGU6ICd0aW1lc3RhbXAnIH0pXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xuXG4gIEBCZWZvcmVJbnNlcnQoKVxuICBAQmVmb3JlVXBkYXRlKClcbiAgYXN5bmMgaGFzaFBhc3N3b3JkKCkge1xuICAgIHRoaXMucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaCh0aGlzLnBhc3N3b3JkLCAxMik7XG4gIH1cblxuICBhc3luYyB2YWxpZGF0ZVBhc3N3b3JkKHBhc3N3b3JkOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICByZXR1cm4gYmNyeXB0LmNvbXBhcmUocGFzc3dvcmQsIHRoaXMucGFzc3dvcmQpO1xuICB9XG59XG4iLCJleHBvcnQgZW51bSBVc2VyU3RhdHVzIHtcbiAgQWN0aXZlID0gJ0F0aXZvJyxcbiAgQmxvY2tlZCA9ICdCbG9xdWVhZG8nLFxuICBJbmFjdGl2ZSA9ICdJbmF0aXZvJyxcbn1cbiIsImltcG9ydCB7IEFnZVNjYWxlIH0gZnJvbSAnLi4vZW51bXMvYWdlLXNjYWxlLmVudW0nO1xuXG5leHBvcnQgY2xhc3MgQWdlU2NhbGVDbGFzcyB7XG4gIHByaXZhdGUgc3RhcnQgPSAnJztcbiAgcHJpdmF0ZSBlbmQgPSAnJztcblxuICBwdWJsaWMgY29uc3RydWN0b3IoYWdlU2NhbGVUeXBlOiBBZ2VTY2FsZSkge1xuICAgIHRoaXMuc2V0RGF0ZXMoYWdlU2NhbGVUeXBlKTtcbiAgfVxuXG4gIGdldFN0YXJ0KCkge1xuICAgIHJldHVybiB0aGlzLnN0YXJ0O1xuICB9XG5cbiAgZ2V0RW5kKCkge1xuICAgIHJldHVybiB0aGlzLmVuZDtcbiAgfVxuXG4gIHNldERhdGVzKGFnZVNjYWxlVHlwZTogQWdlU2NhbGUpIHtcbiAgICBjb25zdCBzdGFydERhdGUgPSBuZXcgRGF0ZSgpO1xuICAgIGNvbnN0IGVuZERhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgY29uc3QgcmFuZ2VEYXRlID0ge1xuICAgICAgQmV0d2VlbjE4QW5kMjY6ICgpID0+IHtcbiAgICAgICAgc3RhcnREYXRlLnNldEZ1bGxZZWFyKHN0YXJ0RGF0ZS5nZXRGdWxsWWVhcigpIC0gMjYpO1xuICAgICAgICBlbmREYXRlLnNldEZ1bGxZZWFyKGVuZERhdGUuZ2V0RnVsbFllYXIoKSAtIDE4KTtcbiAgICAgICAgdGhpcy5zdGFydCA9IHN0YXJ0RGF0ZS50b0lTT1N0cmluZygpO1xuICAgICAgICB0aGlzLmVuZCA9IGVuZERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgIH0sXG4gICAgICBCZXR3ZWVuMjVBbmQzMTogKCkgPT4ge1xuICAgICAgICBzdGFydERhdGUuc2V0RnVsbFllYXIoc3RhcnREYXRlLmdldEZ1bGxZZWFyKCkgLSAzMSk7XG4gICAgICAgIGVuZERhdGUuc2V0RnVsbFllYXIoZW5kRGF0ZS5nZXRGdWxsWWVhcigpIC0gMjUpO1xuICAgICAgICB0aGlzLnN0YXJ0ID0gc3RhcnREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgIHRoaXMuZW5kID0gZW5kRGF0ZS50b0lTT1N0cmluZygpO1xuICAgICAgfSxcbiAgICAgIEJldHdlZW4zMEFuZDM2OiAoKSA9PiB7XG4gICAgICAgIHN0YXJ0RGF0ZS5zZXRGdWxsWWVhcihzdGFydERhdGUuZ2V0RnVsbFllYXIoKSAtIDM2KTtcbiAgICAgICAgZW5kRGF0ZS5zZXRGdWxsWWVhcihlbmREYXRlLmdldEZ1bGxZZWFyKCkgLSAzMCk7XG4gICAgICAgIHRoaXMuc3RhcnQgPSBzdGFydERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgICAgdGhpcy5lbmQgPSBlbmREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICB9LFxuICAgICAgQmV0d2VlbjM1QW5kNDE6ICgpID0+IHtcbiAgICAgICAgc3RhcnREYXRlLnNldEZ1bGxZZWFyKHN0YXJ0RGF0ZS5nZXRGdWxsWWVhcigpIC0gNDEpO1xuICAgICAgICBlbmREYXRlLnNldEZ1bGxZZWFyKGVuZERhdGUuZ2V0RnVsbFllYXIoKSAtIDM1KTtcbiAgICAgICAgdGhpcy5zdGFydCA9IHN0YXJ0RGF0ZS50b0lTT1N0cmluZygpO1xuICAgICAgICB0aGlzLmVuZCA9IGVuZERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgIH0sXG4gICAgICBHcmVhdGVyVGhhbjQwOiAoKSA9PiB7XG4gICAgICAgIGVuZERhdGUuc2V0RnVsbFllYXIoZW5kRGF0ZS5nZXRGdWxsWWVhcigpIC0gNDApO1xuICAgICAgICB0aGlzLmVuZCA9IGVuZERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgIH0sXG4gICAgfTtcblxuICAgIHJhbmdlRGF0ZVthZ2VTY2FsZVR5cGVdLmNhbGwoKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRW50aXR5UmVwb3NpdG9yeSwgUmVwb3NpdG9yeSB9IGZyb20gJ3R5cGVvcm0nO1xuaW1wb3J0IHsgQ3JlYXRlVXNlckR0byB9IGZyb20gJy4uL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVcGRhdGVVc2VyRHRvIH0gZnJvbSAnLi4vZHRvL3VwZGF0ZVVzZXIuZHRvJztcbmltcG9ydCB7IFVzZXJTZWFyY2hCb2R5IH0gZnJvbSAnLi4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyU3RhdHVzIH0gZnJvbSAnLi4vZW51bXMvdXNlci1zdGF0dXMuZW51bSc7XG5pbXBvcnQgeyBBZ2VTY2FsZUNsYXNzIH0gZnJvbSAnLi4vbW9kZWxzL2FnZS1zY2FsZS5tb2RlbCc7XG5pbXBvcnQgeyBzdGFydE9mRGF5LCBlbmRPZkRheSB9IGZyb20gJ2RhdGUtZm5zJztcblxuQEVudGl0eVJlcG9zaXRvcnkoVXNlcilcbmV4cG9ydCBjbGFzcyBVc2VyUmVwb3NpdG9yeSBleHRlbmRzIFJlcG9zaXRvcnk8VXNlcj4ge1xuICBhc3luYyBmaW5kQnlGaWx0ZXJzKFxuICAgIHVzZXJTZWFyY2hCb2R5OiBVc2VyU2VhcmNoQm9keSxcbiAgICBmaXJzdCA9IDAsXG4gICAgc2l6ZSA9IDAsXG4gICk6IFByb21pc2U8VXNlcltdPiB7XG4gICAgaWYgKHVzZXJTZWFyY2hCb2R5KSB7XG4gICAgICBjb25zdCB7IG5hbWUsIGxvZ2luLCBjcGYsIHN0YXR1cywgYWdlU2NhbGUsIGNyZWF0ZWRBdCwgdXBkYXRlZEF0IH0gPVxuICAgICAgICB1c2VyU2VhcmNoQm9keTtcblxuICAgICAgY29uc3QgcXVlcnlCdWlsZGVyID0gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKTtcblxuICAgICAgbGV0IGZpcnN0V2hlcmUgPSB0cnVlO1xuXG4gICAgICBpZiAobmFtZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5uYW1lIGxpa2UgOm5hbWUnLCB7IG5hbWU6IGAlJHtuYW1lfSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIubmFtZSBsaWtlIDpuYW1lJywgeyBuYW1lOiBgJSR7bmFtZX0lYCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAobG9naW4pIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIubG9naW4gbGlrZSA6bG9naW4nLCB7IGxvZ2luOiBgJSR7bG9naW59JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5sb2dpbiBsaWtlIDpsb2dpbicsIHtcbiAgICAgICAgICAgIGxvZ2luOiBgJSR7bG9naW59JWAsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGNwZikge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHN0YXR1cykge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGFnZVNjYWxlKSB7XG4gICAgICAgIGNvbnN0IGFnZVNjYWxlQ2xhc3MgPSBuZXcgQWdlU2NhbGVDbGFzcyhhZ2VTY2FsZSk7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgaWYgKGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmJpcnRoRGF0ZSBCRVRXRUVOIDpzdGFydCBBTkQgOmVuZCcsIHtcbiAgICAgICAgICAgICAgc3RhcnQ6IGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSxcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5iaXJ0aERhdGUgPCA6ZW5kJywge1xuICAgICAgICAgICAgICBlbmQ6IGFnZVNjYWxlQ2xhc3MuZ2V0RW5kKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGlmIChhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCkpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5iaXJ0aERhdGUgQkVUV0VFTiA6c3RhcnQgQU5EIDplbmQnLCB7XG4gICAgICAgICAgICAgIHN0YXJ0OiBhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCksXG4gICAgICAgICAgICAgIGVuZDogYWdlU2NhbGVDbGFzcy5nZXRFbmQoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuYmlydGhEYXRlIDwgOmVuZCcsIHtcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChjcmVhdGVkQXQpIHtcbiAgICAgICAgaWYgKGNyZWF0ZWRBdC5zdGFydCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuY3JlYXRlZEF0ID49IDpjcmVhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIGNyZWF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheShjcmVhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNyZWF0ZWRBdCA+PSA6Y3JlYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkoY3JlYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNyZWF0ZWRBdC5lbmQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNyZWF0ZWRBdCA8PSA6Y3JlYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgY3JlYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkoY3JlYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuY3JlYXRlZEF0IDw9IDpjcmVhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRFbmREYXRlOiBlbmRPZkRheShjcmVhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICh1cGRhdGVkQXQpIHtcbiAgICAgICAgaWYgKHVwZGF0ZWRBdC5zdGFydCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIudXBkYXRlZEF0ID49IDp1cGRhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIHVwZGF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheSh1cGRhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnVwZGF0ZWRBdCA+PSA6dXBkYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkodXBkYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHVwZGF0ZWRBdC5lbmQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnVwZGF0ZWRBdCA8PSA6dXBkYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgdXBkYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkodXBkYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIudXBkYXRlZEF0IDw9IDp1cGRhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRFbmREYXRlOiBlbmRPZkRheSh1cGRhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChzaXplID4gMCkge1xuICAgICAgICBxdWVyeUJ1aWxkZXIuc2tpcChmaXJzdCkudGFrZShzaXplKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGF3YWl0IHF1ZXJ5QnVpbGRlci5nZXRNYW55KCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IHF1ZXJ5QnVpbGRlciA9IHRoaXMuY3JlYXRlUXVlcnlCdWlsZGVyKCd1c2VyJykud2hlcmUoXG4gICAgICAgICd1c2VyLnN0YXR1cyAhPSA6c3RhdHVzJyxcbiAgICAgICAge1xuICAgICAgICAgIHN0YXR1czogVXNlclN0YXR1cy5JbmFjdGl2ZSxcbiAgICAgICAgfSxcbiAgICAgICk7XG5cbiAgICAgIGlmIChzaXplID4gMCkge1xuICAgICAgICBxdWVyeUJ1aWxkZXIuc2tpcChmaXJzdCkudGFrZShzaXplKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGF3YWl0IHF1ZXJ5QnVpbGRlci5nZXRNYW55KCk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgY291bnRCeUZpbHRlcnModXNlclNlYXJjaEJvZHk6IFVzZXJTZWFyY2hCb2R5KTogUHJvbWlzZTxudW1iZXI+IHtcbiAgICBpZiAodXNlclNlYXJjaEJvZHkpIHtcbiAgICAgIGNvbnN0IHsgbmFtZSwgbG9naW4sIGNwZiwgc3RhdHVzLCBhZ2VTY2FsZSwgY3JlYXRlZEF0LCB1cGRhdGVkQXQgfSA9XG4gICAgICAgIHVzZXJTZWFyY2hCb2R5O1xuXG4gICAgICBjb25zdCBxdWVyeUJ1aWxkZXIgPSB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigndXNlcicpO1xuXG4gICAgICBsZXQgZmlyc3RXaGVyZSA9IHRydWU7XG5cbiAgICAgIGlmIChuYW1lKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLm5hbWUgbGlrZSA6bmFtZScsIHsgbmFtZTogYCUke25hbWV9JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5uYW1lIGxpa2UgOm5hbWUnLCB7IG5hbWU6IGAlJHtuYW1lfSVgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChsb2dpbikge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5sb2dpbiBsaWtlIDpsb2dpbicsIHsgbG9naW46IGAlJHtsb2dpbn0lYCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmxvZ2luIGxpa2UgOmxvZ2luJywge1xuICAgICAgICAgICAgbG9naW46IGAlJHtsb2dpbn0lYCxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoY3BmKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNwZiBsaWtlIDpjcGYnLCB7IGNwZjogYCUke2NwZn0lYCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNwZiBsaWtlIDpjcGYnLCB7IGNwZjogYCUke2NwZn0lYCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc3RhdHVzKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnN0YXR1cyA9IDpzdGF0dXMnLCB7IHN0YXR1cyB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnN0YXR1cyA9IDpzdGF0dXMnLCB7IHN0YXR1cyB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoYWdlU2NhbGUpIHtcbiAgICAgICAgY29uc3QgYWdlU2NhbGVDbGFzcyA9IG5ldyBBZ2VTY2FsZUNsYXNzKGFnZVNjYWxlKTtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBpZiAoYWdlU2NhbGVDbGFzcy5nZXRTdGFydCgpKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuYmlydGhEYXRlIEJFVFdFRU4gOnN0YXJ0IEFORCA6ZW5kJywge1xuICAgICAgICAgICAgICBzdGFydDogYWdlU2NhbGVDbGFzcy5nZXRTdGFydCgpLFxuICAgICAgICAgICAgICBlbmQ6IGFnZVNjYWxlQ2xhc3MuZ2V0RW5kKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmJpcnRoRGF0ZSA8IDplbmQnLCB7XG4gICAgICAgICAgICAgIGVuZDogYWdlU2NhbGVDbGFzcy5nZXRFbmQoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgaWYgKGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmJpcnRoRGF0ZSBCRVRXRUVOIDpzdGFydCBBTkQgOmVuZCcsIHtcbiAgICAgICAgICAgICAgc3RhcnQ6IGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSxcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5iaXJ0aERhdGUgPCA6ZW5kJywge1xuICAgICAgICAgICAgICBlbmQ6IGFnZVNjYWxlQ2xhc3MuZ2V0RW5kKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGNyZWF0ZWRBdCkge1xuICAgICAgICBpZiAoY3JlYXRlZEF0LnN0YXJ0KSB7XG4gICAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcmVhdGVkQXQgPj0gOmNyZWF0ZWRBdFN0YXJ0RGF0ZScsIHtcbiAgICAgICAgICAgICAgY3JlYXRlZEF0U3RhcnREYXRlOiBzdGFydE9mRGF5KGNyZWF0ZWRBdC5zdGFydCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuY3JlYXRlZEF0ID49IDpjcmVhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIGNyZWF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheShjcmVhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY3JlYXRlZEF0LmVuZCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuY3JlYXRlZEF0IDw9IDpjcmVhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRFbmREYXRlOiBlbmRPZkRheShjcmVhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcmVhdGVkQXQgPD0gOmNyZWF0ZWRBdEVuZERhdGUnLCB7XG4gICAgICAgICAgICAgIGNyZWF0ZWRBdEVuZERhdGU6IGVuZE9mRGF5KGNyZWF0ZWRBdC5lbmQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHVwZGF0ZWRBdCkge1xuICAgICAgICBpZiAodXBkYXRlZEF0LnN0YXJ0KSB7XG4gICAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci51cGRhdGVkQXQgPj0gOnVwZGF0ZWRBdFN0YXJ0RGF0ZScsIHtcbiAgICAgICAgICAgICAgdXBkYXRlZEF0U3RhcnREYXRlOiBzdGFydE9mRGF5KHVwZGF0ZWRBdC5zdGFydCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIudXBkYXRlZEF0ID49IDp1cGRhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIHVwZGF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheSh1cGRhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodXBkYXRlZEF0LmVuZCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIudXBkYXRlZEF0IDw9IDp1cGRhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRFbmREYXRlOiBlbmRPZkRheSh1cGRhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci51cGRhdGVkQXQgPD0gOnVwZGF0ZWRBdEVuZERhdGUnLCB7XG4gICAgICAgICAgICAgIHVwZGF0ZWRBdEVuZERhdGU6IGVuZE9mRGF5KHVwZGF0ZWRBdC5lbmQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGF3YWl0IHF1ZXJ5QnVpbGRlci5nZXRDb3VudCgpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKVxuICAgICAgICAud2hlcmUoJ3VzZXIuc3RhdHVzICE9IDpzdGF0dXMnLCB7XG4gICAgICAgICAgc3RhdHVzOiBVc2VyU3RhdHVzLkluYWN0aXZlLFxuICAgICAgICB9KVxuICAgICAgICAuZ2V0Q291bnQoKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyB1c2VyQWxyZWFkeUV4aXN0KFxuICAgIGNwZjogc3RyaW5nLFxuICAgIGVtYWlsOiBzdHJpbmcsXG4gICAgbG9naW46IHN0cmluZyxcbiAgKTogUHJvbWlzZTxVc2VyW10+IHtcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKVxuICAgICAgLndoZXJlKCd1c2VyLmNwZiA9IDpjcGYnLCB7IGNwZiB9KVxuICAgICAgLm9yV2hlcmUoJ3VzZXIuZW1haWwgPSA6ZW1haWwnLCB7IGVtYWlsIH0pXG4gICAgICAub3JXaGVyZSgndXNlci5sb2dpbiA9IDpsb2dpbicsIHsgbG9naW4gfSlcbiAgICAgIC5nZXRNYW55KCk7XG4gIH1cblxuICBhc3luYyBjcmVhdGVBbmRTYXZlKHtcbiAgICBuYW1lLFxuICAgIGxvZ2luLFxuICAgIHBhc3N3b3JkLFxuICAgIGVtYWlsLFxuICAgIHBob25lTnVtYmVyLFxuICAgIGNwZixcbiAgICBiaXJ0aERhdGUsXG4gICAgbW90aGVyTmFtZSxcbiAgICBzdGF0dXMsXG4gIH06IENyZWF0ZVVzZXJEdG8pIHtcbiAgICBjb25zdCB1c2VyID0gdGhpcy5jcmVhdGUoKTtcblxuICAgIHVzZXIubmFtZSA9IG5hbWU7XG4gICAgdXNlci5sb2dpbiA9IGxvZ2luO1xuICAgIHVzZXIucGFzc3dvcmQgPSBwYXNzd29yZDtcbiAgICB1c2VyLmVtYWlsID0gZW1haWw7XG4gICAgdXNlci5waG9uZU51bWJlciA9IHBob25lTnVtYmVyO1xuICAgIHVzZXIuY3BmID0gY3BmO1xuICAgIHVzZXIuYmlydGhEYXRlID0gYmlydGhEYXRlO1xuICAgIHVzZXIubW90aGVyTmFtZSA9IG1vdGhlck5hbWU7XG4gICAgdXNlci5zdGF0dXMgPSBzdGF0dXM7XG5cbiAgICBhd2FpdCB0aGlzLmluc2VydCh1c2VyKTtcbiAgfVxuXG4gIGFzeW5jIHVwZGF0ZUFuZFNhdmUoXG4gICAgdXNlcjogVXNlcixcbiAgICB7XG4gICAgICBuYW1lLFxuICAgICAgbG9naW4sXG4gICAgICBwYXNzd29yZCxcbiAgICAgIGVtYWlsLFxuICAgICAgcGhvbmVOdW1iZXIsXG4gICAgICBjcGYsXG4gICAgICBiaXJ0aERhdGUsXG4gICAgICBtb3RoZXJOYW1lLFxuICAgICAgc3RhdHVzLFxuICAgIH06IFVwZGF0ZVVzZXJEdG8sXG4gICkge1xuICAgIHVzZXIubmFtZSA9IG5hbWUgfHwgdXNlci5uYW1lO1xuICAgIHVzZXIubG9naW4gPSBsb2dpbiB8fCB1c2VyLmxvZ2luO1xuICAgIHVzZXIucGFzc3dvcmQgPSBwYXNzd29yZCB8fCB1c2VyLnBhc3N3b3JkO1xuICAgIHVzZXIuZW1haWwgPSBlbWFpbCB8fCB1c2VyLmVtYWlsO1xuICAgIHVzZXIucGhvbmVOdW1iZXIgPSBwaG9uZU51bWJlciB8fCB1c2VyLnBob25lTnVtYmVyO1xuICAgIHVzZXIuY3BmID0gY3BmIHx8IHVzZXIuY3BmO1xuICAgIHVzZXIuYmlydGhEYXRlID0gYmlydGhEYXRlIHx8IHVzZXIuYmlydGhEYXRlO1xuICAgIHVzZXIubW90aGVyTmFtZSA9IG1vdGhlck5hbWUgfHwgdXNlci5tb3RoZXJOYW1lO1xuICAgIHVzZXIuc3RhdHVzID0gc3RhdHVzIHx8IHVzZXIuc3RhdHVzO1xuXG4gICAgYXdhaXQgdGhpcy5zYXZlKHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgY2hhbmdlUGFzc3dvcmRBbmRTYXZlKHVzZXI6IFVzZXIsIG5ld1Bhc3N3b3JkOiBzdHJpbmcpIHtcbiAgICB1c2VyLnBhc3N3b3JkID0gbmV3UGFzc3dvcmQ7XG4gICAgYXdhaXQgdGhpcy5zYXZlKHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgaW5hY3RpdmVBbGxVc2VycygpIHtcbiAgICBhd2FpdCB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigpXG4gICAgICAudXBkYXRlKFVzZXIpXG4gICAgICAuc2V0KHsgc3RhdHVzOiBVc2VyU3RhdHVzLkluYWN0aXZlIH0pXG4gICAgICAuZXhlY3V0ZSgpO1xuICB9XG59XG4iLCJpbXBvcnQge1xuICBCb2R5LFxuICBDb250cm9sbGVyLFxuICBEZWxldGUsXG4gIEdldCxcbiAgUGFyYW0sXG4gIFBvc3QsXG4gIFB1dCxcbiAgUXVlcnksXG4gIFVzZUd1YXJkcyxcbn0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgSnd0QXV0aEd1YXJkIH0gZnJvbSAnYXBwcy9hdXRoL3NyYy9qd3Qvand0LWF1dGguZ3VhcmQnO1xuaW1wb3J0IHsgRGVsZXRlUmVzdWx0IH0gZnJvbSAndHlwZW9ybSc7XG5pbXBvcnQgeyBDcmVhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgUmVjb3ZlclBhc3N3b3JkRHRvIH0gZnJvbSAnLi9kdG8vcmVjb3ZlclBhc3N3b3JkLmR0byc7XG5pbXBvcnQgeyBVcGRhdGVVc2VyRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlckNoYW5nZVJlc3VsdCB9IGZyb20gJy4vZHRvL3VzZXJDaGFuZ2VSZXN1bHQuZHRvJztcbmltcG9ydCB7IFVzZXJSZXNwb25zZUR0byB9IGZyb20gJy4vZHRvL3VzZXJSZXNwb25zZS5kdG8nO1xuaW1wb3J0IHsgVXNlclNlYXJjaEJvZHkgfSBmcm9tICcuL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5pbXBvcnQgeyBVc2VyU3RhdHVzIH0gZnJvbSAnLi9lbnVtcy91c2VyLXN0YXR1cy5lbnVtJztcbmltcG9ydCB7IFVzZXJTZXJ2aWNlIH0gZnJvbSAnLi91c2VyLnNlcnZpY2UnO1xuXG5AQ29udHJvbGxlcignYXBpL3YxL3VzZXJzJylcbmV4cG9ydCBjbGFzcyBVc2VyQ29udHJvbGxlciB7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgdXNlclNlcnZpY2U6IFVzZXJTZXJ2aWNlKSB7fVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSByZXRvcm5hIHRvZG9zIG9zIHVzdcOhcmlvc1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQEdldCgpXG4gIGFzeW5jIGdldFVzZXJzKCk6IFByb21pc2U8VXNlclJlc3BvbnNlRHRvPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZ2V0VXNlcnMoKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSByZXRvcm5hIG9zIHVzdcOhcmlvcyBkZSBmb3JtYSBwYWdpbmFkYSwgcG9zc2liaWxpdGFuZG8gaW5zZXJpciBmaWx0cm9zIG5hIGJ1c2NhXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAUG9zdCgnYnlGaWx0ZXJzJylcbiAgYXN5bmMgZ2V0VXNlcnNCeUZpbHRlcnMoXG4gICAgQEJvZHkoKSB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHksXG4gICAgQFF1ZXJ5KCdmaXJzdCcpIGZpcnN0OiBudW1iZXIsXG4gICAgQFF1ZXJ5KCdzaXplJykgc2l6ZTogbnVtYmVyLFxuICApOiBQcm9taXNlPFVzZXJSZXNwb25zZUR0bz4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmdldFVzZXJzKGZpcnN0LCBzaXplLCB1c2VyU2VhcmNoQm9keSk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBxdWUgcmV0b3JuYSB1bSB1c3XDoXJpbyBwZWxvIHNldSBpZFxuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQEdldCgnOmlkJylcbiAgYXN5bmMgZ2V0VXNlckJ5SWQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5nZXRVc2VyQnlJZChpZCk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBkZSBjcmlhw6fDo28gZGUgdW0gdXN1w6FyaW9cbiAgQFBvc3QoJy8nKVxuICBhc3luYyBjcmVhdGVVc2VyKEBCb2R5KCkgY3JlYXRlVXNlckR0bzogQ3JlYXRlVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmNyZWF0ZVVzZXIoY3JlYXRlVXNlckR0byk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBkZSBhdHVhbGl6YcOnw6NvIGRlIHVtIHVzdcOhcmlvXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAUHV0KCc6aWQnKVxuICBhc3luYyB1cGRhdGVVc2VyKFxuICAgIEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLFxuICAgIEBCb2R5KCkgdXBkYXRlVXNlckR0bzogVXBkYXRlVXNlckR0byxcbiAgKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UudXBkYXRlVXNlcihpZCwgdXBkYXRlVXNlckR0byk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBxdWUgcGVybWl0ZSBhIHVtIHVzdcOhcmlvIHJlY3VwZXJhciBvIHNldSBhY2Vzc28gYWx0ZXJhbmRvIGEgc2VuaGFcbiAgQFB1dCgncGFzc3dvcmQvcmVjb3ZlcicpXG4gIGFzeW5jIHJlY292ZXJQYXNzd29yZChcbiAgICBAQm9keSgpIHJlY292ZXJQYXNzd29yZER0bzogUmVjb3ZlclBhc3N3b3JkRHRvLFxuICApOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5yZWNvdmVyUGFzc3dvcmQocmVjb3ZlclBhc3N3b3JkRHRvKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSBhbHRlcmEgbyBzdGF0dXMgZGUgdW0gdXN1w6FyaW9cbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBQdXQoJzppZC9zdGF0dXMnKVxuICBhc3luYyBjaGFuZ2VVc2VyU3RhdHVzKFxuICAgIEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLFxuICAgIEBCb2R5KCkgeyBzdGF0dXMgfTogeyBzdGF0dXM6IFVzZXJTdGF0dXMgfSxcbiAgKTogUHJvbWlzZTxVc2VyQ2hhbmdlUmVzdWx0PiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuY2hhbmdlVXNlclN0YXR1cyhpZCwgc3RhdHVzKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSBpbmF0aXZhIHRvZG9zIG9zIHVzdcOhcmlvc1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQERlbGV0ZSgnaW5hY3RpdmUnKVxuICBhc3luYyBpbmFjdGl2ZVVzZXJCdWxrKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmluYWN0aXZlVXNlckJ1bGsoKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgZm9yd2FyZFJlZiwgR2xvYmFsLCBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJSZXBvc2l0b3J5IH0gZnJvbSAnLi9yZXBvc2l0b3JpZXMvdXNlci5yZXBvc2l0b3J5JztcbmltcG9ydCB7IFVzZXJDb250cm9sbGVyIH0gZnJvbSAnLi91c2VyLmNvbnRyb2xsZXInO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICcuL3VzZXIuc2VydmljZSc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoTW9kdWxlIH0gZnJvbSAnLi9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5tb2R1bGUnO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJ2FwcHMvYXV0aC9zcmMvYXV0aC5tb2R1bGUnO1xuXG5AR2xvYmFsKClcbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLmZvclJvb3QoeyBpc0dsb2JhbDogdHJ1ZSB9KSxcbiAgICBUeXBlT3JtTW9kdWxlLmZvclJvb3Qoe1xuICAgICAgdHlwZTogJ215c3FsJyxcbiAgICAgIGhvc3Q6ICdteXNxbF91c2VyJyxcbiAgICAgIGRhdGFiYXNlOiAndXNlcnMnLFxuICAgICAgcG9ydDogMzMwNixcbiAgICAgIHVzZXJuYW1lOiAncm9vdCcsXG4gICAgICBwYXNzd29yZDogJ3Jvb3QnLFxuICAgICAgZW50aXRpZXM6IFtVc2VyXSxcbiAgICAgIHN5bmNocm9uaXplOiBmYWxzZSxcbiAgICAgIGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG4gICAgICBkcm9wU2NoZW1hOiBmYWxzZSxcbiAgICAgIG1pZ3JhdGlvbnNSdW46IGZhbHNlLFxuICAgICAgbG9nZ2luZzogWyd3YXJuJywgJ2Vycm9yJ10sXG4gICAgICBjbGk6IHtcbiAgICAgICAgbWlncmF0aW9uc0RpcjogJ2FwcHMvdXNlci9zcmMvbWlncmF0aW9ucycsXG4gICAgICB9LFxuICAgIH0pLFxuICAgIFR5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbVXNlclJlcG9zaXRvcnldKSxcbiAgICBFbGFzdGljU2VhcmNoTW9kdWxlLFxuICAgIGZvcndhcmRSZWYoKCkgPT4gQXV0aE1vZHVsZSksXG4gIF0sXG4gIHByb3ZpZGVyczogW1VzZXJTZXJ2aWNlXSxcbiAgY29udHJvbGxlcnM6IFtVc2VyQ29udHJvbGxlcl0sXG4gIGV4cG9ydHM6IFtVc2VyU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIFVzZXJNb2R1bGUge31cbiIsImltcG9ydCB7XG4gIEZvcmJpZGRlbkV4Y2VwdGlvbixcbiAgSW5qZWN0YWJsZSxcbiAgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbixcbiAgTm90Rm91bmRFeGNlcHRpb24sXG59IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBSZWNvdmVyUGFzc3dvcmREdG8gfSBmcm9tICcuL2R0by9yZWNvdmVyUGFzc3dvcmQuZHRvJztcbmltcG9ydCB7IFVwZGF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyQ2hhbmdlUmVzdWx0IH0gZnJvbSAnLi9kdG8vdXNlckNoYW5nZVJlc3VsdC5kdG8nO1xuaW1wb3J0IHsgVXNlclJlc3BvbnNlRHRvIH0gZnJvbSAnLi9kdG8vdXNlclJlc3BvbnNlLmR0byc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoU2VydmljZSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2guc2VydmljZSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclJlcG9zaXRvcnkgfSBmcm9tICcuL3JlcG9zaXRvcmllcy91c2VyLnJlcG9zaXRvcnknO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVXNlclNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwcml2YXRlIHVzZXJSZXBvc2l0b3J5OiBVc2VyUmVwb3NpdG9yeSxcbiAgICBwcml2YXRlIGVsYXN0aWNTZWFyY2hTZXJ2aWNlOiBFbGFzdGljU2VhcmNoU2VydmljZSxcbiAgKSB7fVxuXG4gIGFzeW5jIGdldFVzZXJzKFxuICAgIGZpcnN0ID0gMCxcbiAgICBzaXplID0gMCxcbiAgICB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHkgPSBudWxsLFxuICApOiBQcm9taXNlPFVzZXJSZXNwb25zZUR0bz4ge1xuICAgIGlmICh1c2VyU2VhcmNoQm9keSkge1xuICAgICAgY29uc3QgeyBhZ2VTY2FsZSwgY3JlYXRlZEF0LCB1cGRhdGVkQXQgfSA9IHVzZXJTZWFyY2hCb2R5O1xuXG4gICAgICBpZiAoYWdlU2NhbGUgfHwgY3JlYXRlZEF0IHx8IHVwZGF0ZWRBdCB8fCB0cnVlKSB7XG4gICAgICAgIGNvbnN0IHVzZXJzID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kQnlGaWx0ZXJzKFxuICAgICAgICAgIHVzZXJTZWFyY2hCb2R5LFxuICAgICAgICAgIGZpcnN0LFxuICAgICAgICAgIHNpemUsXG4gICAgICAgICk7XG5cbiAgICAgICAgY29uc3QgY291bnQgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5KTtcblxuICAgICAgICBjb25zdCB1c2VyUmVzcG9uc2VEdG8gPSBuZXcgVXNlclJlc3BvbnNlRHRvKHVzZXJzLCBjb3VudCk7XG5cbiAgICAgICAgcmV0dXJuIHVzZXJSZXNwb25zZUR0bztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxldCB1c2VyU2VhcmNoQm9keUxpc3Q6IFVzZXJTZWFyY2hCb2R5W10gPSBbXTtcblxuICAgICAgICBsZXQgaW5kZXggPSAxO1xuXG4gICAgICAgIGZvciAoY29uc3QgW2F0dHJpYnV0ZU5hbWUsIGF0dHJpYnV0ZVZhbHVlXSBvZiBPYmplY3QuZW50cmllcyhcbiAgICAgICAgICB1c2VyU2VhcmNoQm9keSxcbiAgICAgICAgKSkge1xuICAgICAgICAgIGlmIChhdHRyaWJ1dGVWYWx1ZSkge1xuICAgICAgICAgICAgY29uc3QgcGFydGlhbFNlYXJjaCA9IGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2Uuc2VhcmNoKFxuICAgICAgICAgICAgICBmaXJzdCxcbiAgICAgICAgICAgICAgc2l6ZSxcbiAgICAgICAgICAgICAgYXR0cmlidXRlVmFsdWUsXG4gICAgICAgICAgICAgIFthdHRyaWJ1dGVOYW1lXSxcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QgPVxuICAgICAgICAgICAgICBpbmRleCA+IDFcbiAgICAgICAgICAgICAgICA/IHBhcnRpYWxTZWFyY2guZmlsdGVyKChpdGVtKSA9PlxuICAgICAgICAgICAgICAgICAgICB1c2VyU2VhcmNoQm9keUxpc3QuaW5jbHVkZXMoaXRlbSksXG4gICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgOiBbLi4ucGFydGlhbFNlYXJjaF07XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHVzZXJSZXNwb25zZUR0byA9IG5ldyBVc2VyUmVzcG9uc2VEdG8oXG4gICAgICAgICAgdXNlclNlYXJjaEJvZHlMaXN0LFxuICAgICAgICAgIHVzZXJTZWFyY2hCb2R5TGlzdC5sZW5ndGgsXG4gICAgICAgICk7XG5cbiAgICAgICAgcmV0dXJuIHVzZXJSZXNwb25zZUR0bztcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gUmV0b3JuYSB0b2RvcyBvcyB1c3XDoXJpb3Mgbm8gZWxhc3RpYyBzZWFyY2ggY29tIG8gc3RhdHVzIGF0aXZvXG4gICAgICAvLyBjb25zdCB1c2VycyA9IGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2Uuc2VhcmNoKFxuICAgICAgLy8gICBmaXJzdCxcbiAgICAgIC8vICAgc2l6ZSxcbiAgICAgIC8vICAgVXNlclN0YXR1cy5BY3RpdmUsXG4gICAgICAvLyAgIFsnc3RhdHVzJ10sXG4gICAgICAvLyApO1xuXG4gICAgICAvLyBjb25zdCB7IGNvdW50IH0gPSBhd2FpdCB0aGlzLmVsYXN0aWNTZWFyY2hTZXJ2aWNlLmNvdW50KFxuICAgICAgLy8gICBVc2VyU3RhdHVzLkFjdGl2ZSxcbiAgICAgIC8vICAgWydzdGF0dXMnXSxcbiAgICAgIC8vICk7XG4gICAgICAvLyBjb25zdCB1c2VyUmVzcG9uc2VEdG8gPSBuZXcgVXNlclJlc3BvbnNlRHRvKHVzZXJzLCBjb3VudCk7XG4gICAgICAvLyByZXR1cm4gdXNlclJlc3BvbnNlRHRvO1xuXG4gICAgICAvLyBSZXRvcm5hIHRvZG9zIG9zIHVzdcOhcmlvcyBjb20gbyBzdGF0dXMgYXRpdm8sIGRlIGZvcm1hIHBhZ2luYWRhXG4gICAgICBjb25zdCB1c2VycyA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZEJ5RmlsdGVycyhcbiAgICAgICAgdXNlclNlYXJjaEJvZHksXG4gICAgICAgIGZpcnN0LFxuICAgICAgICBzaXplLFxuICAgICAgKTtcblxuICAgICAgY29uc3QgY291bnQgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5KTtcblxuICAgICAgY29uc3QgdXNlclJlc3BvbnNlRHRvID0gbmV3IFVzZXJSZXNwb25zZUR0byh1c2VycywgY291bnQpO1xuXG4gICAgICByZXR1cm4gdXNlclJlc3BvbnNlRHRvO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGdldFVzZXJCeUlkKGlkOiBzdHJpbmcpOiBQcm9taXNlPFVzZXI+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKGlkKTtcblxuICAgIGlmICghdXNlcikge1xuICAgICAgdGhyb3cgbmV3IE5vdEZvdW5kRXhjZXB0aW9uKCdOw6NvIGV4aXN0ZSB1bSB1c3XDoXJpbyBjb20gbyBpZCBwYXNzYWRvJyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHVzZXI7XG4gIH1cblxuICBhc3luYyBjcmVhdGVVc2VyKGNyZWF0ZVVzZXJEdG86IENyZWF0ZVVzZXJEdG8pOiBQcm9taXNlPFVzZXI+IHtcbiAgICBjb25zdCB7IGNwZiwgZW1haWwsIGxvZ2luIH0gPSBjcmVhdGVVc2VyRHRvO1xuXG4gICAgY29uc3QgdXNlckFscmVhZHlFeGlzdCA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkudXNlckFscmVhZHlFeGlzdChcbiAgICAgIGNwZixcbiAgICAgIGVtYWlsLFxuICAgICAgbG9naW4sXG4gICAgKTtcblxuICAgIGlmICh1c2VyQWxyZWFkeUV4aXN0ICYmIHVzZXJBbHJlYWR5RXhpc3QubGVuZ3RoKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihcbiAgICAgICAgYErDoSBleGlzdGUgdW0gdXN1w6FyaW8gY2FkYXN0cmFkbyBjb20gbyBjcGYsIGVtYWlsIG91IGxvZ2luIHBhc3NhZG9zYCxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuY3JlYXRlQW5kU2F2ZShjcmVhdGVVc2VyRHRvKTtcblxuICAgICAgY29uc3QgY3JlYXRlZFVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgICB3aGVyZTogeyBsb2dpbiB9LFxuICAgICAgfSk7XG5cbiAgICAgIC8vIGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2UuaW5kZXgoY3JlYXRlZFVzZXIpO1xuXG4gICAgICByZXR1cm4gY3JlYXRlZFVzZXI7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHVwZGF0ZVVzZXIoaWQ6IHN0cmluZywgdXBkYXRlVXNlckR0bzogVXBkYXRlVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgY3BmLCBlbWFpbCwgbG9naW4gfSA9IHVwZGF0ZVVzZXJEdG87XG5cbiAgICBjb25zdCB1c2VyQWxyZWFkeUV4aXN0ID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51c2VyQWxyZWFkeUV4aXN0KFxuICAgICAgY3BmLFxuICAgICAgZW1haWwsXG4gICAgICBsb2dpbixcbiAgICApO1xuXG4gICAgaWYgKHVzZXJBbHJlYWR5RXhpc3QgJiYgdXNlckFscmVhZHlFeGlzdC5sZW5ndGgpIHtcbiAgICAgIGNvbnN0IHJlYWxseUFub3RoZXJVc2VyID0gdXNlckFscmVhZHlFeGlzdC5maW5kKCh1c2VyKSA9PiB1c2VyLmlkICE9PSBpZCk7XG5cbiAgICAgIGlmIChyZWFsbHlBbm90aGVyVXNlcikge1xuICAgICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihcbiAgICAgICAgICBgSsOhIGV4aXN0ZSB1bSB1c3XDoXJpbyBjYWRhc3RyYWRvIGNvbSBvIGNwZiwgZW1haWwgb3UgbG9naW4gcGFzc2Fkb3NgLFxuICAgICAgICApO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoaWQpO1xuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkudXBkYXRlQW5kU2F2ZSh1c2VyLCB1cGRhdGVVc2VyRHRvKTtcblxuICAgICAgY29uc3QgdXBkYXRlZFVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgICB3aGVyZTogeyBsb2dpbiB9LFxuICAgICAgfSk7XG5cbiAgICAgIC8vIGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2UudXBkYXRlKHVwZGF0ZWRVc2VyKTtcblxuICAgICAgcmV0dXJuIHVwZGF0ZWRVc2VyO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oZXJyLnNxbE1lc3NhZ2UgfHwgZXJyKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyByZWNvdmVyUGFzc3dvcmQocmVjb3ZlclBhc3N3b3JkRHRvOiBSZWNvdmVyUGFzc3dvcmREdG8pOiBQcm9taXNlPFVzZXI+IHtcbiAgICBjb25zdCB7IGNwZiwgZW1haWwsIG5hbWUsIG5ld1Bhc3N3b3JkIH0gPSByZWNvdmVyUGFzc3dvcmREdG87XG5cbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKHtcbiAgICAgIHdoZXJlOiB7XG4gICAgICAgIGNwZixcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBpZiAoIXVzZXIgfHwgdXNlci5lbWFpbCAhPT0gZW1haWwgfHwgdXNlci5uYW1lICE9PSBuYW1lKSB7XG4gICAgICB0aHJvdyBuZXcgRm9yYmlkZGVuRXhjZXB0aW9uKCdBcyBpbmZvcm1hw6fDtWVzIHBhc3NhZGFzIGVzdMOjbyBpbmNvcnJldGFzJyk7XG4gICAgfVxuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuY2hhbmdlUGFzc3dvcmRBbmRTYXZlKHVzZXIsIG5ld1Bhc3N3b3JkKTtcblxuICAgICAgcmV0dXJuIHVzZXI7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGZpbmRCeUxvZ2luKGxvZ2luOiBzdHJpbmcpOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKHtcbiAgICAgIHdoZXJlOiB7XG4gICAgICAgIGxvZ2luLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGNoYW5nZVVzZXJTdGF0dXMoXG4gICAgaWQ6IHN0cmluZyxcbiAgICB1c2VyU3RhdHVzOiBVc2VyU3RhdHVzLFxuICApOiBQcm9taXNlPFVzZXJDaGFuZ2VSZXN1bHQ+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kT25lKGlkKTtcblxuICAgIGlmICghdXNlcikge1xuICAgICAgdGhyb3cgbmV3IE5vdEZvdW5kRXhjZXB0aW9uKCdVc3XDoXJpbyBuw6NvIGV4aXN0ZScpO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBjb25zdCB1cGRhdGVVc2VyRHRvID0gbmV3IFVwZGF0ZVVzZXJEdG8oKTtcbiAgICAgIHVwZGF0ZVVzZXJEdG8uc3RhdHVzID0gdXNlclN0YXR1cztcblxuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51cGRhdGVBbmRTYXZlKHVzZXIsIHVwZGF0ZVVzZXJEdG8pO1xuXG4gICAgICBjb25zdCB1c2VyQ2hhbmdlUmVzdWx0OiBVc2VyQ2hhbmdlUmVzdWx0ID0ge1xuICAgICAgICBhZmZlY3RlZDogMSxcbiAgICAgIH07XG5cbiAgICAgIHJldHVybiB1c2VyQ2hhbmdlUmVzdWx0O1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oZXJyLnNxbE1lc3NhZ2UgfHwgZXJyKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBpbmFjdGl2ZVVzZXJCdWxrKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5pbmFjdGl2ZUFsbFVzZXJzKCk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmxvZyhlcnIpO1xuICAgICAgdGhyb3cgbmV3IEludGVybmFsU2VydmVyRXJyb3JFeGNlcHRpb24oZXJyLnNxbE1lc3NhZ2UgfHwgZXJyKTtcbiAgICB9XG4gIH1cbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29uZmlnXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29yZVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2VsYXN0aWNzZWFyY2hcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9qd3RcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9wYXNzcG9ydFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3R5cGVvcm1cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiYmNyeXB0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImNsYXNzLXZhbGlkYXRvclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJkYXRlLWZuc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJwYXNzcG9ydC1qd3RcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwidHlwZW9ybVwiKTsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiaW1wb3J0IHsgVmFsaWRhdGlvblBpcGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBOZXN0RmFjdG9yeSB9IGZyb20gJ0BuZXN0anMvY29yZSc7XG5pbXBvcnQgeyBVc2VyTW9kdWxlIH0gZnJvbSAnLi91c2VyLm1vZHVsZSc7XG5cbmFzeW5jIGZ1bmN0aW9uIGJvb3RzdHJhcCgpIHtcbiAgY29uc3QgYXBwID0gYXdhaXQgTmVzdEZhY3RvcnkuY3JlYXRlKFVzZXJNb2R1bGUpO1xuICBhcHAudXNlR2xvYmFsUGlwZXMobmV3IFZhbGlkYXRpb25QaXBlKCkpO1xuICBhcHAuZW5hYmxlQ29ycyh7IG9yaWdpbjogWydodHRwOi8vbG9jYWxob3N0OjQyMDAnXSB9KTtcbiAgYXdhaXQgYXBwLmxpc3RlbigzMDAwKTtcbn1cbmJvb3RzdHJhcCgpO1xuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9