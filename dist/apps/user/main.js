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
            const users = await this.userRepository.findByFilters(userSearchBody, first, size);
            const count = await this.userRepository.countByFilters(userSearchBody);
            const userResponseDto = new userResponse_dto_1.UserResponseDto(users, count);
            return userResponseDto;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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TSxHQUFHLEdBQUcsTUFBTSxrQkFBVyxDQUFDLE1BQU0sQ0FBQyx3QkFBVSxDQUFDLENBQUM7SUFDakQsR0FBRyxDQUFDLGNBQWMsQ0FBQyxJQUFJLHVCQUFjLEVBQUUsQ0FBQyxDQUFDO0lBQ3pDLEdBQUcsQ0FBQyxVQUFVLENBQUMsRUFBRSxNQUFNLEVBQUUsQ0FBQyx1QkFBdUIsQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0RCxNQUFNLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDekIsQ0FBQztBQUNELFNBQVMsRUFBRSxDQUFDIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGguY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvYXV0aC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL2F1dGgvc3JjL2F1dGguc2VydmljZS50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvYXV0aC9zcmMvand0L2p3dC1hdXRoLmd1YXJkLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy9hdXRoL3NyYy9qd3Qvand0LnN0cmF0ZWd5LnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vY3JlYXRlVXNlci5kdG8udHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vcmVjb3ZlclBhc3N3b3JkLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZHRvL3VwZGF0ZVVzZXIuZHRvLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9kdG8vdXNlclJlc3BvbnNlLmR0by50cyIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS8uL2FwcHMvdXNlci9zcmMvZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2gubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5zZXJ2aWNlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbGFzdGljLXNlYXJjaC9pbnRlcmZhY2VzL3VzZXJTZWFyY2hCb2R5LnR5cGUudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL2VudGl0aWVzL3VzZXIuZW50aXR5LnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9lbnVtcy91c2VyLXN0YXR1cy5lbnVtLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9tb2RlbHMvYWdlLXNjYWxlLm1vZGVsLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9yZXBvc2l0b3JpZXMvdXNlci5yZXBvc2l0b3J5LnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy91c2VyLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvLi9hcHBzL3VzZXIvc3JjL3VzZXIubW9kdWxlLnRzIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy91c2VyLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vblwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb25maWdcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29yZVwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9lbGFzdGljc2VhcmNoXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2p3dFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9wYXNzcG9ydFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vZmN4bGFicy1jaGFsbGVuZ2UvZXh0ZXJuYWwgY29tbW9uanMgXCJiY3J5cHRcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXZhbGlkYXRvclwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwiZGF0ZS1mbnNcIiIsIndlYnBhY2s6Ly9mY3hsYWJzLWNoYWxsZW5nZS9leHRlcm5hbCBjb21tb25qcyBcInBhc3Nwb3J0LWp3dFwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL2V4dGVybmFsIGNvbW1vbmpzIFwidHlwZW9ybVwiIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2ZjeGxhYnMtY2hhbGxlbmdlLy4vYXBwcy91c2VyL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIFBvc3QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBMb2dpblVzZXJEdG8gfSBmcm9tICdhcHBzL3VzZXIvc3JjL2R0by9sb2dpblVzZXIuZHRvJztcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnO1xuXG5AQ29udHJvbGxlcignYXBpL3YxL2F1dGgnKVxuZXhwb3J0IGNsYXNzIEF1dGhDb250cm9sbGVyIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBhdXRoU2VydmljZTogQXV0aFNlcnZpY2UpIHt9XG5cbiAgQFBvc3QoJ2xvZ2luJylcbiAgYXN5bmMgbG9naW4oXG4gICAgQEJvZHkoKSBsb2dpblVzZXJEdG86IExvZ2luVXNlckR0byxcbiAgKTogUHJvbWlzZTx7IGFjY2Vzc1Rva2VuOiBzdHJpbmcgfT4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luVXNlckR0byk7XG4gIH1cbn1cbiIsImltcG9ydCB7IGZvcndhcmRSZWYsIE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IENvbmZpZ01vZHVsZSwgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJztcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0JztcbmltcG9ydCB7IFBhc3Nwb3J0TW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9wYXNzcG9ydCc7XG5pbXBvcnQgeyBVc2VyTW9kdWxlIH0gZnJvbSAnYXBwcy91c2VyL3NyYy91c2VyLm1vZHVsZSc7XG5pbXBvcnQgeyBBdXRoQ29udHJvbGxlciB9IGZyb20gJy4vYXV0aC5jb250cm9sbGVyJztcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnO1xuaW1wb3J0IHsgSnd0U3RyYXRlZ3kgfSBmcm9tICcuL2p3dC9qd3Quc3RyYXRlZ3knO1xuXG5ATW9kdWxlKHtcbiAgaW1wb3J0czogW1xuICAgIENvbmZpZ01vZHVsZS5mb3JSb290KHsgaXNHbG9iYWw6IHRydWUgfSksXG4gICAgUGFzc3BvcnRNb2R1bGUsXG4gICAgSnd0TW9kdWxlLnJlZ2lzdGVyQXN5bmMoe1xuICAgICAgaW1wb3J0czogW0NvbmZpZ01vZHVsZV0sXG4gICAgICB1c2VGYWN0b3J5OiBhc3luYyAoKSA9PiAoe1xuICAgICAgICBzZWNyZXQ6IHByb2Nlc3MuZW52LkpXVF9TRUNSRVQsXG4gICAgICB9KSxcbiAgICAgIGluamVjdDogW0NvbmZpZ1NlcnZpY2VdLFxuICAgIH0pLFxuICAgIGZvcndhcmRSZWYoKCkgPT4gVXNlck1vZHVsZSksXG4gIF0sXG4gIGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuICBwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0U3RyYXRlZ3ldLFxuICBleHBvcnRzOiBbQXV0aFNlcnZpY2UsIEp3dFN0cmF0ZWd5XSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7fVxuIiwiaW1wb3J0IHtcbiAgSW5qZWN0YWJsZSxcbiAgTm90Rm91bmRFeGNlcHRpb24sXG4gIFVuYXV0aG9yaXplZEV4Y2VwdGlvbixcbn0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgSnd0U2VydmljZSB9IGZyb20gJ0BuZXN0anMvand0JztcbmltcG9ydCB7IExvZ2luVXNlckR0byB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZHRvL2xvZ2luVXNlci5kdG8nO1xuaW1wb3J0IHsgVXNlciB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJ2FwcHMvdXNlci9zcmMvZW51bXMvdXNlci1zdGF0dXMuZW51bSc7XG5pbXBvcnQgeyBVc2VyU2VydmljZSB9IGZyb20gJ2FwcHMvdXNlci9zcmMvdXNlci5zZXJ2aWNlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcbiAgY29uc3RydWN0b3IoXG4gICAgcHJpdmF0ZSB1c2VyU2VydmljZTogVXNlclNlcnZpY2UsXG4gICAgcHJpdmF0ZSBqd3RTZXJ2aWNlOiBKd3RTZXJ2aWNlLFxuICApIHt9XG5cbiAgYXN5bmMgbG9naW4obG9naW5Vc2VyRHRvOiBMb2dpblVzZXJEdG8pOiBQcm9taXNlPHsgYWNjZXNzVG9rZW46IHN0cmluZyB9PiB7XG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudmFsaWRhdGVVc2VyKGxvZ2luVXNlckR0byk7XG5cbiAgICBjb25zdCBwYXlsb2FkID0ge1xuICAgICAgdXNlcklkOiB1c2VyLmlkLFxuICAgIH07XG5cbiAgICByZXR1cm4ge1xuICAgICAgYWNjZXNzVG9rZW46IHRoaXMuand0U2VydmljZS5zaWduKHBheWxvYWQpLFxuICAgIH07XG4gIH1cblxuICAvLyBWYWxpZGEgc2UgdW0gdXN1w6FyaW8gZXhpc3RlIGUgcGFzc291IGFzIGNyZWRlbmNpYWlzIGNvcnJldGFzIG5vIGxvZ2luXG4gIGFzeW5jIHZhbGlkYXRlVXNlcihsb2dpblVzZXJEdG86IExvZ2luVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgbG9naW4sIHBhc3N3b3JkIH0gPSBsb2dpblVzZXJEdG87XG5cbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy51c2VyU2VydmljZS5maW5kQnlMb2dpbihsb2dpbik7XG5cbiAgICBpZiAoIXVzZXIpIHtcbiAgICAgIHRocm93IG5ldyBOb3RGb3VuZEV4Y2VwdGlvbignVXN1w6FyaW8gbsOjbyBlbmNvbnRyYWRvJyk7XG4gICAgfVxuXG4gICAgaWYgKHVzZXIuc3RhdHVzICE9PSBVc2VyU3RhdHVzLkFjdGl2ZSkge1xuICAgICAgdGhyb3cgbmV3IFVuYXV0aG9yaXplZEV4Y2VwdGlvbihcbiAgICAgICAgYEVzc2UgdXN1w6FyaW8gZXN0w6EgY29tIG8gc3RhdHVzICR7dXNlci5zdGF0dXMudmFsdWVPZigpfWAsXG4gICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IHZhbGlkYXRlUGFzc3dvcmQgPSBhd2FpdCB1c2VyLnZhbGlkYXRlUGFzc3dvcmQocGFzc3dvcmQpO1xuXG4gICAgaWYgKCF2YWxpZGF0ZVBhc3N3b3JkKSB7XG4gICAgICB0aHJvdyBuZXcgVW5hdXRob3JpemVkRXhjZXB0aW9uKCdMb2dpbiBvdSBzZW5oYSBpbmNvcnJldG9zJyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHVzZXI7XG4gIH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBBdXRoR3VhcmQgfSBmcm9tICdAbmVzdGpzL3Bhc3Nwb3J0JztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEp3dEF1dGhHdWFyZCBleHRlbmRzIEF1dGhHdWFyZCgnand0Jykge31cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBQYXNzcG9ydFN0cmF0ZWd5IH0gZnJvbSAnQG5lc3Rqcy9wYXNzcG9ydCc7XG5pbXBvcnQgeyBFeHRyYWN0Snd0LCBTdHJhdGVneSB9IGZyb20gJ3Bhc3Nwb3J0LWp3dCc7XG5pbXBvcnQgeyBKd3RQYXlsb2FkIH0gZnJvbSAnLi9qd3QucGF5bG9hZCc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBKd3RTdHJhdGVneSBleHRlbmRzIFBhc3Nwb3J0U3RyYXRlZ3koU3RyYXRlZ3kpIHtcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgc3VwZXIoe1xuICAgICAgand0RnJvbVJlcXVlc3Q6IEV4dHJhY3RKd3QuZnJvbUF1dGhIZWFkZXJBc0JlYXJlclRva2VuKCksXG4gICAgICBpZ25vcmVFeHBpcmF0aW9uOiBmYWxzZSxcbiAgICAgIHNlY3JldE9yS2V5OiBwcm9jZXNzLmVudi5KV1RfU0VDUkVULFxuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgdmFsaWRhdGUocGF5bG9hZDogSnd0UGF5bG9hZCk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHVzZXJJZDogcGF5bG9hZC51c2VySWQsXG4gICAgfTtcbiAgfVxufVxuIiwiaW1wb3J0IHtcbiAgSXNFbWFpbCxcbiAgSXNFbnVtLFxuICBJc05vdEVtcHR5LFxuICBJc09wdGlvbmFsLFxuICBJc1Bob25lTnVtYmVyLFxuICBJc1N0cmluZyxcbn0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuLi9lbnVtcy91c2VyLXN0YXR1cy5lbnVtJztcblxuZXhwb3J0IGNsYXNzIENyZWF0ZVVzZXJEdG8ge1xuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIG5hbWU6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIGxvZ2luOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBwYXNzd29yZDogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzRW1haWwoKVxuICBlbWFpbDogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzUGhvbmVOdW1iZXIoKVxuICBwaG9uZU51bWJlcjogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgY3BmOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBASXNTdHJpbmcoKVxuICBiaXJ0aERhdGU6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIG1vdGhlck5hbWU6IHN0cmluZztcblxuICBASXNPcHRpb25hbCgpXG4gIEBJc0VudW0oVXNlclN0YXR1cylcbiAgc3RhdHVzOiBVc2VyU3RhdHVzO1xufVxuIiwiaW1wb3J0IHsgSXNOb3RFbXB0eSB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcic7XG5cbmV4cG9ydCBjbGFzcyBMb2dpblVzZXJEdG8ge1xuICBASXNOb3RFbXB0eSgpXG4gIGxvZ2luOiBzdHJpbmc7XG5cbiAgQElzTm90RW1wdHkoKVxuICBwYXNzd29yZDogc3RyaW5nO1xufVxuIiwiaW1wb3J0IHtcbiAgSXNFbWFpbCxcbiAgSXNFbnVtLFxuICBJc05vdEVtcHR5LFxuICBJc09wdGlvbmFsLFxuICBJc1Bob25lTnVtYmVyLFxuICBJc1N0cmluZyxcbn0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJztcbmV4cG9ydCBjbGFzcyBSZWNvdmVyUGFzc3dvcmREdG8ge1xuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIG5hbWU6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc0VtYWlsKClcbiAgZW1haWw6IHN0cmluZztcblxuICBASXNOb3RFbXB0eSgpXG4gIEBJc1N0cmluZygpXG4gIGNwZjogc3RyaW5nO1xuXG4gIEBJc05vdEVtcHR5KClcbiAgQElzU3RyaW5nKClcbiAgbmV3UGFzc3dvcmQ6IHN0cmluZztcbn1cbiIsImltcG9ydCB7IElzU3RyaW5nIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2NyZWF0ZVVzZXIuZHRvJztcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZVVzZXJEdG8gZXh0ZW5kcyBDcmVhdGVVc2VyRHRvIHtcbiAgQElzU3RyaW5nKClcbiAgcGFzc3dvcmQ6IHN0cmluZztcbn1cbiIsImltcG9ydCB7IFVzZXJTZWFyY2hCb2R5IH0gZnJvbSAnLi4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuLi9lbnRpdGllcy91c2VyLmVudGl0eSc7XG5cbmV4cG9ydCBjbGFzcyBVc2VyUmVzcG9uc2VEdG8ge1xuICBkYXRhOiBVc2VyW10gfCBVc2VyU2VhcmNoQm9keVtdO1xuICBjb3VudDogbnVtYmVyO1xuXG4gIHB1YmxpYyBjb25zdHJ1Y3RvcihkYXRhOiBVc2VyW10gfCBVc2VyU2VhcmNoQm9keVtdLCBjb3VudDogbnVtYmVyKSB7XG4gICAgdGhpcy5kYXRhID0gZGF0YTtcbiAgICB0aGlzLmNvdW50ID0gY291bnQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IENvbmZpZ01vZHVsZSwgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJztcbmltcG9ydCB7IEVsYXN0aWNTZWFyY2hTZXJ2aWNlIH0gZnJvbSAnLi9lbGFzdGljLXNlYXJjaC5zZXJ2aWNlJztcbmltcG9ydCB7IEVsYXN0aWNzZWFyY2hNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2VsYXN0aWNzZWFyY2gnO1xuXG5ATW9kdWxlKHtcbiAgaW1wb3J0czogW1xuICAgIENvbmZpZ01vZHVsZSxcbiAgICBFbGFzdGljc2VhcmNoTW9kdWxlLnJlZ2lzdGVyQXN5bmMoe1xuICAgICAgaW1wb3J0czogW0NvbmZpZ01vZHVsZV0sXG4gICAgICB1c2VGYWN0b3J5OiBhc3luYyAoY29uZmlnU2VydmljZTogQ29uZmlnU2VydmljZSkgPT4gKHtcbiAgICAgICAgbm9kZTogY29uZmlnU2VydmljZS5nZXQoJ0VMQVNUSUNTRUFSQ0hfTk9ERScpLFxuICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgdXNlcm5hbWU6IGNvbmZpZ1NlcnZpY2UuZ2V0KCdFTEFTVElDU0VBUkNIX1VTRVJOQU1FJyksXG4gICAgICAgICAgcGFzc3dvcmQ6IGNvbmZpZ1NlcnZpY2UuZ2V0KCdFTEFTVElDU0VBUkNIX1BBU1NXT1JEJyksXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIGluamVjdDogW0NvbmZpZ1NlcnZpY2VdLFxuICAgIH0pLFxuICBdLFxuICBwcm92aWRlcnM6IFtFbGFzdGljU2VhcmNoU2VydmljZV0sXG4gIGV4cG9ydHM6IFtFbGFzdGljU2VhcmNoU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEVsYXN0aWNTZWFyY2hNb2R1bGUge31cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBFbGFzdGljc2VhcmNoU2VydmljZSB9IGZyb20gJ0BuZXN0anMvZWxhc3RpY3NlYXJjaCc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi4vZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlckNvdW50UmVzdWx0IH0gZnJvbSAnLi9pbnRlcmZhY2VzL3VzZXJDb3VudFJlc3VsdC50eXBlJztcbmltcG9ydCB7IFVzZXJTZWFyY2hCb2R5IH0gZnJvbSAnLi9pbnRlcmZhY2VzL3VzZXJTZWFyY2hCb2R5LnR5cGUnO1xuaW1wb3J0IHsgVXNlclNlYXJjaFJlc3VsdCB9IGZyb20gJy4vaW50ZXJmYWNlcy91c2VyU2VhcmNoUmVzdWx0LnR5cGUnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRWxhc3RpY1NlYXJjaFNlcnZpY2Uge1xuICBjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGVsYXN0aWNzZWFyY2hTZXJ2aWNlOiBFbGFzdGljc2VhcmNoU2VydmljZSkge31cblxuICBhc3luYyBzZWFyY2goXG4gICAgZmlyc3Q6IG51bWJlcixcbiAgICBzaXplOiBudW1iZXIsXG4gICAgdGV4dDogc3RyaW5nLFxuICAgIGZpZWxkczogc3RyaW5nW10sXG4gICk6IFByb21pc2U8VXNlclNlYXJjaEJvZHlbXT4ge1xuICAgIGNvbnN0IHsgYm9keSB9ID0gYXdhaXQgdGhpcy5lbGFzdGljc2VhcmNoU2VydmljZS5zZWFyY2g8VXNlclNlYXJjaFJlc3VsdD4oe1xuICAgICAgaW5kZXg6ICd1c2VycycsXG4gICAgICBmcm9tOiBmaXJzdCxcbiAgICAgIHNpemUsXG4gICAgICBib2R5OiB7XG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgbXVsdGlfbWF0Y2g6IHtcbiAgICAgICAgICAgIHF1ZXJ5OiB0ZXh0LFxuICAgICAgICAgICAgZmllbGRzLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuICAgIGNvbnN0IGhpdHMgPSBib2R5LmhpdHMuaGl0cztcbiAgICByZXR1cm4gaGl0cy5tYXAoKGl0ZW0pID0+IGl0ZW0uX3NvdXJjZSk7XG4gIH1cblxuICBhc3luYyBjb3VudCh0ZXh0OiBzdHJpbmcsIGZpZWxkczogc3RyaW5nW10pOiBQcm9taXNlPFVzZXJDb3VudFJlc3VsdD4ge1xuICAgIGNvbnN0IHsgYm9keSB9ID0gYXdhaXQgdGhpcy5lbGFzdGljc2VhcmNoU2VydmljZS5jb3VudDxVc2VyQ291bnRSZXN1bHQ+KHtcbiAgICAgIGluZGV4OiAndXNlcnMnLFxuICAgICAgYm9keToge1xuICAgICAgICBxdWVyeToge1xuICAgICAgICAgIG11bHRpX21hdGNoOiB7XG4gICAgICAgICAgICBxdWVyeTogdGV4dCxcbiAgICAgICAgICAgIGZpZWxkcyxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIHJldHVybiBib2R5O1xuICB9XG5cbiAgYXN5bmMgaW5kZXgoeyBpZCwgbmFtZSwgbG9naW4sIGNwZiwgc3RhdHVzLCBiaXJ0aERhdGUgfTogVXNlcikge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLmVsYXN0aWNzZWFyY2hTZXJ2aWNlLmluZGV4KHtcbiAgICAgIGluZGV4OiAndXNlcnMnLFxuICAgICAgYm9keToge1xuICAgICAgICBpZCxcbiAgICAgICAgbmFtZSxcbiAgICAgICAgbG9naW4sXG4gICAgICAgIGNwZixcbiAgICAgICAgc3RhdHVzLFxuICAgICAgICBiaXJ0aERhdGUsXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgdXBkYXRlKHVzZXI6IFVzZXIpIHtcbiAgICBhd2FpdCB0aGlzLnJlbW92ZSh1c2VyLmlkKTtcbiAgICBhd2FpdCB0aGlzLmluZGV4KHVzZXIpO1xuICB9XG5cbiAgYXN5bmMgcmVtb3ZlKHVzZXJJZDogc3RyaW5nKSB7XG4gICAgdGhpcy5lbGFzdGljc2VhcmNoU2VydmljZS5kZWxldGVCeVF1ZXJ5KHtcbiAgICAgIGluZGV4OiAndXNlcnMnLFxuICAgICAgYm9keToge1xuICAgICAgICBxdWVyeToge1xuICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICBpZDogdXNlcklkLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBBZ2VTY2FsZSB9IGZyb20gJy4uLy4uL2VudW1zL2FnZS1zY2FsZS5lbnVtJztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuLi8uLi9lbnVtcy91c2VyLXN0YXR1cy5lbnVtJztcblxuZXhwb3J0IGludGVyZmFjZSBVc2VyU2VhcmNoQm9keSB7XG4gIGlkOiBzdHJpbmc7XG4gIG5hbWU6IHN0cmluZztcbiAgbG9naW46IHN0cmluZztcbiAgY3BmOiBzdHJpbmc7XG4gIHN0YXR1czogVXNlclN0YXR1cztcbiAgYWdlU2NhbGU6IEFnZVNjYWxlO1xuICBjcmVhdGVkQXQ/OiB7XG4gICAgc3RhcnQ6IG51bWJlcjtcbiAgICBlbmQ6IG51bWJlcjtcbiAgfTtcbiAgdXBkYXRlZEF0Pzoge1xuICAgIHN0YXJ0OiBudW1iZXI7XG4gICAgZW5kOiBudW1iZXI7XG4gIH07XG59XG4iLCJpbXBvcnQge1xuICBFbnRpdHksXG4gIENvbHVtbixcbiAgUHJpbWFyeUdlbmVyYXRlZENvbHVtbixcbiAgQmVmb3JlSW5zZXJ0LFxuICBVcGRhdGVEYXRlQ29sdW1uLFxuICBCZWZvcmVVcGRhdGUsXG59IGZyb20gJ3R5cGVvcm0nO1xuaW1wb3J0ICogYXMgYmNyeXB0IGZyb20gJ2JjcnlwdCc7XG5pbXBvcnQgeyBDcmVhdGVVc2VyRHRvIH0gZnJvbSAnLi4vZHRvL2NyZWF0ZVVzZXIuZHRvJztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuLi9lbnVtcy91c2VyLXN0YXR1cy5lbnVtJztcblxuQEVudGl0eSgpXG5leHBvcnQgY2xhc3MgVXNlciB7XG4gIEBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uKCd1dWlkJylcbiAgaWQ6IHN0cmluZztcblxuICBAQ29sdW1uKCd2YXJjaGFyJylcbiAgbmFtZTogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBsb2dpbjogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBwYXNzd29yZDogc3RyaW5nO1xuXG4gIEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIHR5cGU6ICd2YXJjaGFyJyB9KVxuICBlbWFpbDogc3RyaW5nO1xuXG4gIEBDb2x1bW4oJ3ZhcmNoYXInKVxuICBwaG9uZU51bWJlcjogc3RyaW5nO1xuXG4gIEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIHR5cGU6ICd2YXJjaGFyJywgbGVuZ3RoOiAxMSB9KVxuICBjcGY6IHN0cmluZztcblxuICBAQ29sdW1uKCdkYXRlJylcbiAgYmlydGhEYXRlOiBzdHJpbmc7XG5cbiAgQENvbHVtbigndmFyY2hhcicpXG4gIG1vdGhlck5hbWU6IHN0cmluZztcblxuICBAQ29sdW1uKHsgdHlwZTogJ2VudW0nLCBlbnVtOiBVc2VyU3RhdHVzIH0pXG4gIHN0YXR1czogVXNlclN0YXR1cztcblxuICBAQ29sdW1uKHsgdHlwZTogJ3RpbWVzdGFtcCcsIGRlZmF1bHQ6ICgpID0+ICdDVVJSRU5UX1RJTUVTVEFNUCcgfSlcbiAgY3JlYXRlZEF0OiBzdHJpbmc7XG5cbiAgQFVwZGF0ZURhdGVDb2x1bW4oeyB0eXBlOiAndGltZXN0YW1wJyB9KVxuICB1cGRhdGVkQXQ6IHN0cmluZztcblxuICBAQmVmb3JlSW5zZXJ0KClcbiAgQEJlZm9yZVVwZGF0ZSgpXG4gIGFzeW5jIGhhc2hQYXNzd29yZCgpIHtcbiAgICB0aGlzLnBhc3N3b3JkID0gYXdhaXQgYmNyeXB0Lmhhc2godGhpcy5wYXNzd29yZCwgMTIpO1xuICB9XG5cbiAgYXN5bmMgdmFsaWRhdGVQYXNzd29yZChwYXNzd29yZDogc3RyaW5nKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgcmV0dXJuIGJjcnlwdC5jb21wYXJlKHBhc3N3b3JkLCB0aGlzLnBhc3N3b3JkKTtcbiAgfVxufVxuIiwiZXhwb3J0IGVudW0gVXNlclN0YXR1cyB7XG4gIEFjdGl2ZSA9ICdBdGl2bycsXG4gIEJsb2NrZWQgPSAnQmxvcXVlYWRvJyxcbiAgSW5hY3RpdmUgPSAnSW5hdGl2bycsXG59XG4iLCJpbXBvcnQgeyBBZ2VTY2FsZSB9IGZyb20gJy4uL2VudW1zL2FnZS1zY2FsZS5lbnVtJztcblxuZXhwb3J0IGNsYXNzIEFnZVNjYWxlQ2xhc3Mge1xuICBwcml2YXRlIHN0YXJ0ID0gJyc7XG4gIHByaXZhdGUgZW5kID0gJyc7XG5cbiAgcHVibGljIGNvbnN0cnVjdG9yKGFnZVNjYWxlVHlwZTogQWdlU2NhbGUpIHtcbiAgICB0aGlzLnNldERhdGVzKGFnZVNjYWxlVHlwZSk7XG4gIH1cblxuICBnZXRTdGFydCgpIHtcbiAgICByZXR1cm4gdGhpcy5zdGFydDtcbiAgfVxuXG4gIGdldEVuZCgpIHtcbiAgICByZXR1cm4gdGhpcy5lbmQ7XG4gIH1cblxuICBzZXREYXRlcyhhZ2VTY2FsZVR5cGU6IEFnZVNjYWxlKSB7XG4gICAgY29uc3Qgc3RhcnREYXRlID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCBlbmREYXRlID0gbmV3IERhdGUoKTtcblxuICAgIGNvbnN0IHJhbmdlRGF0ZSA9IHtcbiAgICAgIEJldHdlZW4xOEFuZDI2OiAoKSA9PiB7XG4gICAgICAgIHN0YXJ0RGF0ZS5zZXRGdWxsWWVhcihzdGFydERhdGUuZ2V0RnVsbFllYXIoKSAtIDI2KTtcbiAgICAgICAgZW5kRGF0ZS5zZXRGdWxsWWVhcihlbmREYXRlLmdldEZ1bGxZZWFyKCkgLSAxOCk7XG4gICAgICAgIHRoaXMuc3RhcnQgPSBzdGFydERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgICAgdGhpcy5lbmQgPSBlbmREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICB9LFxuICAgICAgQmV0d2VlbjI1QW5kMzE6ICgpID0+IHtcbiAgICAgICAgc3RhcnREYXRlLnNldEZ1bGxZZWFyKHN0YXJ0RGF0ZS5nZXRGdWxsWWVhcigpIC0gMzEpO1xuICAgICAgICBlbmREYXRlLnNldEZ1bGxZZWFyKGVuZERhdGUuZ2V0RnVsbFllYXIoKSAtIDI1KTtcbiAgICAgICAgdGhpcy5zdGFydCA9IHN0YXJ0RGF0ZS50b0lTT1N0cmluZygpO1xuICAgICAgICB0aGlzLmVuZCA9IGVuZERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgIH0sXG4gICAgICBCZXR3ZWVuMzBBbmQzNjogKCkgPT4ge1xuICAgICAgICBzdGFydERhdGUuc2V0RnVsbFllYXIoc3RhcnREYXRlLmdldEZ1bGxZZWFyKCkgLSAzNik7XG4gICAgICAgIGVuZERhdGUuc2V0RnVsbFllYXIoZW5kRGF0ZS5nZXRGdWxsWWVhcigpIC0gMzApO1xuICAgICAgICB0aGlzLnN0YXJ0ID0gc3RhcnREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgIHRoaXMuZW5kID0gZW5kRGF0ZS50b0lTT1N0cmluZygpO1xuICAgICAgfSxcbiAgICAgIEJldHdlZW4zNUFuZDQxOiAoKSA9PiB7XG4gICAgICAgIHN0YXJ0RGF0ZS5zZXRGdWxsWWVhcihzdGFydERhdGUuZ2V0RnVsbFllYXIoKSAtIDQxKTtcbiAgICAgICAgZW5kRGF0ZS5zZXRGdWxsWWVhcihlbmREYXRlLmdldEZ1bGxZZWFyKCkgLSAzNSk7XG4gICAgICAgIHRoaXMuc3RhcnQgPSBzdGFydERhdGUudG9JU09TdHJpbmcoKTtcbiAgICAgICAgdGhpcy5lbmQgPSBlbmREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICB9LFxuICAgICAgR3JlYXRlclRoYW40MDogKCkgPT4ge1xuICAgICAgICBlbmREYXRlLnNldEZ1bGxZZWFyKGVuZERhdGUuZ2V0RnVsbFllYXIoKSAtIDQwKTtcbiAgICAgICAgdGhpcy5lbmQgPSBlbmREYXRlLnRvSVNPU3RyaW5nKCk7XG4gICAgICB9LFxuICAgIH07XG5cbiAgICByYW5nZURhdGVbYWdlU2NhbGVUeXBlXS5jYWxsKCk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEVudGl0eVJlcG9zaXRvcnksIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuLi9kdG8vY3JlYXRlVXNlci5kdG8nO1xuaW1wb3J0IHsgVXBkYXRlVXNlckR0byB9IGZyb20gJy4uL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4uL2VsYXN0aWMtc2VhcmNoL2ludGVyZmFjZXMvdXNlclNlYXJjaEJvZHkudHlwZSc7XG5pbXBvcnQgeyBVc2VyIH0gZnJvbSAnLi4vZW50aXRpZXMvdXNlci5lbnRpdHknO1xuaW1wb3J0IHsgVXNlclN0YXR1cyB9IGZyb20gJy4uL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgQWdlU2NhbGVDbGFzcyB9IGZyb20gJy4uL21vZGVscy9hZ2Utc2NhbGUubW9kZWwnO1xuaW1wb3J0IHsgc3RhcnRPZkRheSwgZW5kT2ZEYXkgfSBmcm9tICdkYXRlLWZucyc7XG5cbkBFbnRpdHlSZXBvc2l0b3J5KFVzZXIpXG5leHBvcnQgY2xhc3MgVXNlclJlcG9zaXRvcnkgZXh0ZW5kcyBSZXBvc2l0b3J5PFVzZXI+IHtcbiAgLy8gQnVzY2Egb3MgdXN1w6FyaW9zLCBkZSBmb3JtYSBwYWdpbmFkYSwgYXRyYXbDqXMgZG9zIGZpbHRyb3MgcGFzc2Fkb3NcbiAgYXN5bmMgZmluZEJ5RmlsdGVycyhcbiAgICB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHksXG4gICAgZmlyc3QgPSAwLFxuICAgIHNpemUgPSAwLFxuICApOiBQcm9taXNlPFVzZXJbXT4ge1xuICAgIGlmICh1c2VyU2VhcmNoQm9keSkge1xuICAgICAgY29uc3QgeyBuYW1lLCBsb2dpbiwgY3BmLCBzdGF0dXMsIGFnZVNjYWxlLCBjcmVhdGVkQXQsIHVwZGF0ZWRBdCB9ID1cbiAgICAgICAgdXNlclNlYXJjaEJvZHk7XG5cbiAgICAgIGNvbnN0IHF1ZXJ5QnVpbGRlciA9IHRoaXMuY3JlYXRlUXVlcnlCdWlsZGVyKCd1c2VyJyk7XG5cbiAgICAgIGxldCBmaXJzdFdoZXJlID0gdHJ1ZTtcblxuICAgICAgaWYgKG5hbWUpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIubmFtZSBsaWtlIDpuYW1lJywgeyBuYW1lOiBgJSR7bmFtZX0lYCB9KTtcbiAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLm5hbWUgbGlrZSA6bmFtZScsIHsgbmFtZTogYCUke25hbWV9JWAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGxvZ2luKSB7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmxvZ2luIGxpa2UgOmxvZ2luJywgeyBsb2dpbjogYCUke2xvZ2lufSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIubG9naW4gbGlrZSA6bG9naW4nLCB7XG4gICAgICAgICAgICBsb2dpbjogYCUke2xvZ2lufSVgLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChjcGYpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuY3BmIGxpa2UgOmNwZicsIHsgY3BmOiBgJSR7Y3BmfSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuY3BmIGxpa2UgOmNwZicsIHsgY3BmOiBgJSR7Y3BmfSVgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChzdGF0dXMpIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuc3RhdHVzID0gOnN0YXR1cycsIHsgc3RhdHVzIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuc3RhdHVzID0gOnN0YXR1cycsIHsgc3RhdHVzIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChhZ2VTY2FsZSkge1xuICAgICAgICBjb25zdCBhZ2VTY2FsZUNsYXNzID0gbmV3IEFnZVNjYWxlQ2xhc3MoYWdlU2NhbGUpO1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIGlmIChhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCkpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5iaXJ0aERhdGUgQkVUV0VFTiA6c3RhcnQgQU5EIDplbmQnLCB7XG4gICAgICAgICAgICAgIHN0YXJ0OiBhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCksXG4gICAgICAgICAgICAgIGVuZDogYWdlU2NhbGVDbGFzcy5nZXRFbmQoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuYmlydGhEYXRlIDwgOmVuZCcsIHtcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBpZiAoYWdlU2NhbGVDbGFzcy5nZXRTdGFydCgpKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuYmlydGhEYXRlIEJFVFdFRU4gOnN0YXJ0IEFORCA6ZW5kJywge1xuICAgICAgICAgICAgICBzdGFydDogYWdlU2NhbGVDbGFzcy5nZXRTdGFydCgpLFxuICAgICAgICAgICAgICBlbmQ6IGFnZVNjYWxlQ2xhc3MuZ2V0RW5kKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmJpcnRoRGF0ZSA8IDplbmQnLCB7XG4gICAgICAgICAgICAgIGVuZDogYWdlU2NhbGVDbGFzcy5nZXRFbmQoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoY3JlYXRlZEF0KSB7XG4gICAgICAgIGlmIChjcmVhdGVkQXQuc3RhcnQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNyZWF0ZWRBdCA+PSA6Y3JlYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkoY3JlYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcmVhdGVkQXQgPj0gOmNyZWF0ZWRBdFN0YXJ0RGF0ZScsIHtcbiAgICAgICAgICAgICAgY3JlYXRlZEF0U3RhcnREYXRlOiBzdGFydE9mRGF5KGNyZWF0ZWRBdC5zdGFydCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChjcmVhdGVkQXQuZW5kKSB7XG4gICAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcmVhdGVkQXQgPD0gOmNyZWF0ZWRBdEVuZERhdGUnLCB7XG4gICAgICAgICAgICAgIGNyZWF0ZWRBdEVuZERhdGU6IGVuZE9mRGF5KGNyZWF0ZWRBdC5lbmQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNyZWF0ZWRBdCA8PSA6Y3JlYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgY3JlYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkoY3JlYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAodXBkYXRlZEF0KSB7XG4gICAgICAgIGlmICh1cGRhdGVkQXQuc3RhcnQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnVwZGF0ZWRBdCA+PSA6dXBkYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkodXBkYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBmaXJzdFdoZXJlID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci51cGRhdGVkQXQgPj0gOnVwZGF0ZWRBdFN0YXJ0RGF0ZScsIHtcbiAgICAgICAgICAgICAgdXBkYXRlZEF0U3RhcnREYXRlOiBzdGFydE9mRGF5KHVwZGF0ZWRBdC5zdGFydCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh1cGRhdGVkQXQuZW5kKSB7XG4gICAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci51cGRhdGVkQXQgPD0gOnVwZGF0ZWRBdEVuZERhdGUnLCB7XG4gICAgICAgICAgICAgIHVwZGF0ZWRBdEVuZERhdGU6IGVuZE9mRGF5KHVwZGF0ZWRBdC5lbmQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnVwZGF0ZWRBdCA8PSA6dXBkYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgdXBkYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkodXBkYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc2l6ZSA+IDApIHtcbiAgICAgICAgcXVlcnlCdWlsZGVyLnNraXAoZmlyc3QpLnRha2Uoc2l6ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhd2FpdCBxdWVyeUJ1aWxkZXIuZ2V0TWFueSgpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25zdCBxdWVyeUJ1aWxkZXIgPSB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigndXNlcicpLndoZXJlKFxuICAgICAgICAndXNlci5zdGF0dXMgIT0gOnN0YXR1cycsXG4gICAgICAgIHtcbiAgICAgICAgICBzdGF0dXM6IFVzZXJTdGF0dXMuSW5hY3RpdmUsXG4gICAgICAgIH0sXG4gICAgICApO1xuXG4gICAgICBpZiAoc2l6ZSA+IDApIHtcbiAgICAgICAgcXVlcnlCdWlsZGVyLnNraXAoZmlyc3QpLnRha2Uoc2l6ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhd2FpdCBxdWVyeUJ1aWxkZXIuZ2V0TWFueSgpO1xuICAgIH1cbiAgfVxuXG4gIC8vIENvbnRhIG8gdG90YWwgZGUgdXN1w6FyaW9zIGF0cmF2w6lzIGRvcyBmaWx0cm9zIHBhc3NhZG9zXG4gIGFzeW5jIGNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5OiBVc2VyU2VhcmNoQm9keSk6IFByb21pc2U8bnVtYmVyPiB7XG4gICAgaWYgKHVzZXJTZWFyY2hCb2R5KSB7XG4gICAgICBjb25zdCB7IG5hbWUsIGxvZ2luLCBjcGYsIHN0YXR1cywgYWdlU2NhbGUsIGNyZWF0ZWRBdCwgdXBkYXRlZEF0IH0gPVxuICAgICAgICB1c2VyU2VhcmNoQm9keTtcblxuICAgICAgY29uc3QgcXVlcnlCdWlsZGVyID0gdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoJ3VzZXInKTtcblxuICAgICAgbGV0IGZpcnN0V2hlcmUgPSB0cnVlO1xuXG4gICAgICBpZiAobmFtZSkge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5uYW1lIGxpa2UgOm5hbWUnLCB7IG5hbWU6IGAlJHtuYW1lfSVgIH0pO1xuICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIubmFtZSBsaWtlIDpuYW1lJywgeyBuYW1lOiBgJSR7bmFtZX0lYCB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAobG9naW4pIHtcbiAgICAgICAgaWYgKGZpcnN0V2hlcmUpIHtcbiAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIubG9naW4gbGlrZSA6bG9naW4nLCB7IGxvZ2luOiBgJSR7bG9naW59JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5sb2dpbiBsaWtlIDpsb2dpbicsIHtcbiAgICAgICAgICAgIGxvZ2luOiBgJSR7bG9naW59JWAsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGNwZikge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5jcGYgbGlrZSA6Y3BmJywgeyBjcGY6IGAlJHtjcGZ9JWAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHN0YXR1cykge1xuICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5zdGF0dXMgPSA6c3RhdHVzJywgeyBzdGF0dXMgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGFnZVNjYWxlKSB7XG4gICAgICAgIGNvbnN0IGFnZVNjYWxlQ2xhc3MgPSBuZXcgQWdlU2NhbGVDbGFzcyhhZ2VTY2FsZSk7XG4gICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgaWYgKGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmJpcnRoRGF0ZSBCRVRXRUVOIDpzdGFydCBBTkQgOmVuZCcsIHtcbiAgICAgICAgICAgICAgc3RhcnQ6IGFnZVNjYWxlQ2xhc3MuZ2V0U3RhcnQoKSxcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci53aGVyZSgndXNlci5iaXJ0aERhdGUgPCA6ZW5kJywge1xuICAgICAgICAgICAgICBlbmQ6IGFnZVNjYWxlQ2xhc3MuZ2V0RW5kKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGlmIChhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCkpIHtcbiAgICAgICAgICAgIHF1ZXJ5QnVpbGRlci5hbmRXaGVyZSgndXNlci5iaXJ0aERhdGUgQkVUV0VFTiA6c3RhcnQgQU5EIDplbmQnLCB7XG4gICAgICAgICAgICAgIHN0YXJ0OiBhZ2VTY2FsZUNsYXNzLmdldFN0YXJ0KCksXG4gICAgICAgICAgICAgIGVuZDogYWdlU2NhbGVDbGFzcy5nZXRFbmQoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuYmlydGhEYXRlIDwgOmVuZCcsIHtcbiAgICAgICAgICAgICAgZW5kOiBhZ2VTY2FsZUNsYXNzLmdldEVuZCgpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChjcmVhdGVkQXQpIHtcbiAgICAgICAgaWYgKGNyZWF0ZWRBdC5zdGFydCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIuY3JlYXRlZEF0ID49IDpjcmVhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIGNyZWF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheShjcmVhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLmNyZWF0ZWRBdCA+PSA6Y3JlYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkoY3JlYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNyZWF0ZWRBdC5lbmQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLmNyZWF0ZWRBdCA8PSA6Y3JlYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgY3JlYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkoY3JlYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIuY3JlYXRlZEF0IDw9IDpjcmVhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICBjcmVhdGVkQXRFbmREYXRlOiBlbmRPZkRheShjcmVhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICh1cGRhdGVkQXQpIHtcbiAgICAgICAgaWYgKHVwZGF0ZWRBdC5zdGFydCkge1xuICAgICAgICAgIGlmIChmaXJzdFdoZXJlKSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIud2hlcmUoJ3VzZXIudXBkYXRlZEF0ID49IDp1cGRhdGVkQXRTdGFydERhdGUnLCB7XG4gICAgICAgICAgICAgIHVwZGF0ZWRBdFN0YXJ0RGF0ZTogc3RhcnRPZkRheSh1cGRhdGVkQXQuc3RhcnQpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGZpcnN0V2hlcmUgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLmFuZFdoZXJlKCd1c2VyLnVwZGF0ZWRBdCA+PSA6dXBkYXRlZEF0U3RhcnREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRTdGFydERhdGU6IHN0YXJ0T2ZEYXkodXBkYXRlZEF0LnN0YXJ0KS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHVwZGF0ZWRBdC5lbmQpIHtcbiAgICAgICAgICBpZiAoZmlyc3RXaGVyZSkge1xuICAgICAgICAgICAgcXVlcnlCdWlsZGVyLndoZXJlKCd1c2VyLnVwZGF0ZWRBdCA8PSA6dXBkYXRlZEF0RW5kRGF0ZScsIHtcbiAgICAgICAgICAgICAgdXBkYXRlZEF0RW5kRGF0ZTogZW5kT2ZEYXkodXBkYXRlZEF0LmVuZCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZmlyc3RXaGVyZSA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBxdWVyeUJ1aWxkZXIuYW5kV2hlcmUoJ3VzZXIudXBkYXRlZEF0IDw9IDp1cGRhdGVkQXRFbmREYXRlJywge1xuICAgICAgICAgICAgICB1cGRhdGVkQXRFbmREYXRlOiBlbmRPZkRheSh1cGRhdGVkQXQuZW5kKS50b0lTT1N0cmluZygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhd2FpdCBxdWVyeUJ1aWxkZXIuZ2V0Q291bnQoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlUXVlcnlCdWlsZGVyKCd1c2VyJylcbiAgICAgICAgLndoZXJlKCd1c2VyLnN0YXR1cyAhPSA6c3RhdHVzJywge1xuICAgICAgICAgIHN0YXR1czogVXNlclN0YXR1cy5JbmFjdGl2ZSxcbiAgICAgICAgfSlcbiAgICAgICAgLmdldENvdW50KCk7XG4gICAgfVxuICB9XG5cbiAgLy8gVmVyaWZpY2Egc2UgdW0gdXN1w6FyaW8gasOhIGV4aXN0ZSBuYSBiYXNlIGRlIGRhZG9zXG4gIGFzeW5jIHVzZXJBbHJlYWR5RXhpc3QoXG4gICAgY3BmOiBzdHJpbmcsXG4gICAgZW1haWw6IHN0cmluZyxcbiAgICBsb2dpbjogc3RyaW5nLFxuICApOiBQcm9taXNlPFVzZXJbXT4ge1xuICAgIHJldHVybiB0aGlzLmNyZWF0ZVF1ZXJ5QnVpbGRlcigndXNlcicpXG4gICAgICAud2hlcmUoJ3VzZXIuY3BmID0gOmNwZicsIHsgY3BmIH0pXG4gICAgICAub3JXaGVyZSgndXNlci5lbWFpbCA9IDplbWFpbCcsIHsgZW1haWwgfSlcbiAgICAgIC5vcldoZXJlKCd1c2VyLmxvZ2luID0gOmxvZ2luJywgeyBsb2dpbiB9KVxuICAgICAgLmdldE1hbnkoKTtcbiAgfVxuXG4gIC8vIFNhbHZhIHVtIG5vdm8gdXN1w6FyaW8gbmEgYmFzZSBkZSBkYWRvc1xuICBhc3luYyBjcmVhdGVBbmRTYXZlKHtcbiAgICBuYW1lLFxuICAgIGxvZ2luLFxuICAgIHBhc3N3b3JkLFxuICAgIGVtYWlsLFxuICAgIHBob25lTnVtYmVyLFxuICAgIGNwZixcbiAgICBiaXJ0aERhdGUsXG4gICAgbW90aGVyTmFtZSxcbiAgICBzdGF0dXMsXG4gIH06IENyZWF0ZVVzZXJEdG8pIHtcbiAgICBjb25zdCB1c2VyID0gdGhpcy5jcmVhdGUoKTtcblxuICAgIHVzZXIubmFtZSA9IG5hbWU7XG4gICAgdXNlci5sb2dpbiA9IGxvZ2luO1xuICAgIHVzZXIucGFzc3dvcmQgPSBwYXNzd29yZDtcbiAgICB1c2VyLmVtYWlsID0gZW1haWw7XG4gICAgdXNlci5waG9uZU51bWJlciA9IHBob25lTnVtYmVyO1xuICAgIHVzZXIuY3BmID0gY3BmO1xuICAgIHVzZXIuYmlydGhEYXRlID0gYmlydGhEYXRlO1xuICAgIHVzZXIubW90aGVyTmFtZSA9IG1vdGhlck5hbWU7XG4gICAgdXNlci5zdGF0dXMgPSBzdGF0dXM7XG5cbiAgICBhd2FpdCB0aGlzLmluc2VydCh1c2VyKTtcbiAgfVxuXG4gIC8vIEF0dWFsaXphIG9zIGRhZG9zIGRlIHVtIHVzdcOhcmlvIGrDoSBleGlzdGVudGUgbmEgYmFzZSBkZSBkYWRvc1xuICBhc3luYyB1cGRhdGVBbmRTYXZlKFxuICAgIHVzZXI6IFVzZXIsXG4gICAge1xuICAgICAgbmFtZSxcbiAgICAgIGxvZ2luLFxuICAgICAgcGFzc3dvcmQsXG4gICAgICBlbWFpbCxcbiAgICAgIHBob25lTnVtYmVyLFxuICAgICAgY3BmLFxuICAgICAgYmlydGhEYXRlLFxuICAgICAgbW90aGVyTmFtZSxcbiAgICAgIHN0YXR1cyxcbiAgICB9OiBVcGRhdGVVc2VyRHRvLFxuICApIHtcbiAgICB1c2VyLm5hbWUgPSBuYW1lIHx8IHVzZXIubmFtZTtcbiAgICB1c2VyLmxvZ2luID0gbG9naW4gfHwgdXNlci5sb2dpbjtcbiAgICB1c2VyLnBhc3N3b3JkID0gcGFzc3dvcmQgfHwgdXNlci5wYXNzd29yZDtcbiAgICB1c2VyLmVtYWlsID0gZW1haWwgfHwgdXNlci5lbWFpbDtcbiAgICB1c2VyLnBob25lTnVtYmVyID0gcGhvbmVOdW1iZXIgfHwgdXNlci5waG9uZU51bWJlcjtcbiAgICB1c2VyLmNwZiA9IGNwZiB8fCB1c2VyLmNwZjtcbiAgICB1c2VyLmJpcnRoRGF0ZSA9IGJpcnRoRGF0ZSB8fCB1c2VyLmJpcnRoRGF0ZTtcbiAgICB1c2VyLm1vdGhlck5hbWUgPSBtb3RoZXJOYW1lIHx8IHVzZXIubW90aGVyTmFtZTtcbiAgICB1c2VyLnN0YXR1cyA9IHN0YXR1cyB8fCB1c2VyLnN0YXR1cztcblxuICAgIGF3YWl0IHRoaXMuc2F2ZSh1c2VyKTtcbiAgfVxuXG4gIC8vIEFsdGVyYSBhIHNlbmhhIGRlIHVtIHVzdcOhcmlvIChyZWN1cGVyYcOnw6NvIGRlIHNlbmhhKVxuICBhc3luYyBjaGFuZ2VQYXNzd29yZEFuZFNhdmUodXNlcjogVXNlciwgbmV3UGFzc3dvcmQ6IHN0cmluZykge1xuICAgIHVzZXIucGFzc3dvcmQgPSBuZXdQYXNzd29yZDtcbiAgICBhd2FpdCB0aGlzLnNhdmUodXNlcik7XG4gIH1cblxuICAvLyBJbmF0aXZhIHRvZG9zIG9zIHVzdcOhcmlvcyBkbyBzaXN0ZW1hXG4gIGFzeW5jIGluYWN0aXZlQWxsVXNlcnMoKSB7XG4gICAgYXdhaXQgdGhpcy5jcmVhdGVRdWVyeUJ1aWxkZXIoKVxuICAgICAgLnVwZGF0ZShVc2VyKVxuICAgICAgLnNldCh7IHN0YXR1czogVXNlclN0YXR1cy5JbmFjdGl2ZSB9KVxuICAgICAgLmV4ZWN1dGUoKTtcbiAgfVxufVxuIiwiaW1wb3J0IHtcbiAgQm9keSxcbiAgQ29udHJvbGxlcixcbiAgRGVsZXRlLFxuICBHZXQsXG4gIFBhcmFtLFxuICBQb3N0LFxuICBQdXQsXG4gIFF1ZXJ5LFxuICBVc2VHdWFyZHMsXG59IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IEp3dEF1dGhHdWFyZCB9IGZyb20gJ2FwcHMvYXV0aC9zcmMvand0L2p3dC1hdXRoLmd1YXJkJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBSZWNvdmVyUGFzc3dvcmREdG8gfSBmcm9tICcuL2R0by9yZWNvdmVyUGFzc3dvcmQuZHRvJztcbmltcG9ydCB7IFVwZGF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyQ2hhbmdlUmVzdWx0IH0gZnJvbSAnLi9kdG8vdXNlckNoYW5nZVJlc3VsdC5kdG8nO1xuaW1wb3J0IHsgVXNlclJlc3BvbnNlRHRvIH0gZnJvbSAnLi9kdG8vdXNlclJlc3BvbnNlLmR0byc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICcuL3VzZXIuc2VydmljZSc7XG5cbkBDb250cm9sbGVyKCdhcGkvdjEvdXNlcnMnKVxuZXhwb3J0IGNsYXNzIFVzZXJDb250cm9sbGVyIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSB1c2VyU2VydmljZTogVXNlclNlcnZpY2UpIHt9XG5cbiAgLy8gQSBzaW50YXhlIFwiQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXCIgcHJvdGVnZSBvcyBlbmRwb2ludHMgZGEgYXBpIGRlIHVzdcOhcmlvcyBjb25mb3JtZSBpbXBsZW1lbnRhZG8gZW0gbmEgYXBsaWNhw6fDo28gQXV0aFNlcnZpY2UsIHBlcm1pdGluZG8gYXBlbmFzIHVzdcOhcmlvcyBsb2dhZG9zIGNvbnN1bHRhcmVtLlxuXG4gIC8vIFNlcnZpw6dvIHF1ZSByZXRvcm5hIHRvZG9zIG9zIHVzdcOhcmlvc1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQEdldCgpXG4gIGFzeW5jIGdldFVzZXJzKCk6IFByb21pc2U8VXNlclJlc3BvbnNlRHRvPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuZ2V0VXNlcnMoKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSByZXRvcm5hIG9zIHVzdcOhcmlvcyBkZSBmb3JtYSBwYWdpbmFkYSwgcG9zc2liaWxpdGFuZG8gaW5zZXJpciBmaWx0cm9zIG5hIGJ1c2NhXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAUG9zdCgnYnlGaWx0ZXJzJylcbiAgYXN5bmMgZ2V0VXNlcnNCeUZpbHRlcnMoXG4gICAgQEJvZHkoKSB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHksXG4gICAgQFF1ZXJ5KCdmaXJzdCcpIGZpcnN0OiBudW1iZXIsXG4gICAgQFF1ZXJ5KCdzaXplJykgc2l6ZTogbnVtYmVyLFxuICApOiBQcm9taXNlPFVzZXJSZXNwb25zZUR0bz4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmdldFVzZXJzKGZpcnN0LCBzaXplLCB1c2VyU2VhcmNoQm9keSk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBxdWUgcmV0b3JuYSB1bSB1c3XDoXJpbyBwZWxvIHNldSBpZFxuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQEdldCgnOmlkJylcbiAgYXN5bmMgZ2V0VXNlckJ5SWQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5nZXRVc2VyQnlJZChpZCk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBkZSBjcmlhw6fDo28gZGUgdW0gdXN1w6FyaW9cbiAgQFBvc3QoJy8nKVxuICBhc3luYyBjcmVhdGVVc2VyKEBCb2R5KCkgY3JlYXRlVXNlckR0bzogQ3JlYXRlVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmNyZWF0ZVVzZXIoY3JlYXRlVXNlckR0byk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBkZSBhdHVhbGl6YcOnw6NvIGRlIHVtIHVzdcOhcmlvXG4gIEBVc2VHdWFyZHMoSnd0QXV0aEd1YXJkKVxuICBAUHV0KCc6aWQnKVxuICBhc3luYyB1cGRhdGVVc2VyKFxuICAgIEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLFxuICAgIEBCb2R5KCkgdXBkYXRlVXNlckR0bzogVXBkYXRlVXNlckR0byxcbiAgKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UudXBkYXRlVXNlcihpZCwgdXBkYXRlVXNlckR0byk7XG4gIH1cblxuICAvLyBTZXJ2acOnbyBxdWUgcGVybWl0ZSBhIHVtIHVzdcOhcmlvIHJlY3VwZXJhciBvIHNldSBhY2Vzc28gYWx0ZXJhbmRvIGEgc2VuaGFcbiAgQFB1dCgncGFzc3dvcmQvcmVjb3ZlcicpXG4gIGFzeW5jIHJlY292ZXJQYXNzd29yZChcbiAgICBAQm9keSgpIHJlY292ZXJQYXNzd29yZER0bzogUmVjb3ZlclBhc3N3b3JkRHRvLFxuICApOiBQcm9taXNlPFVzZXI+IHtcbiAgICByZXR1cm4gYXdhaXQgdGhpcy51c2VyU2VydmljZS5yZWNvdmVyUGFzc3dvcmQocmVjb3ZlclBhc3N3b3JkRHRvKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSBhbHRlcmEgbyBzdGF0dXMgZGUgdW0gdXN1w6FyaW9cbiAgQFVzZUd1YXJkcyhKd3RBdXRoR3VhcmQpXG4gIEBQdXQoJzppZC9zdGF0dXMnKVxuICBhc3luYyBjaGFuZ2VVc2VyU3RhdHVzKFxuICAgIEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLFxuICAgIEBCb2R5KCkgeyBzdGF0dXMgfTogeyBzdGF0dXM6IFVzZXJTdGF0dXMgfSxcbiAgKTogUHJvbWlzZTxVc2VyQ2hhbmdlUmVzdWx0PiB7XG4gICAgcmV0dXJuIGF3YWl0IHRoaXMudXNlclNlcnZpY2UuY2hhbmdlVXNlclN0YXR1cyhpZCwgc3RhdHVzKTtcbiAgfVxuXG4gIC8vIFNlcnZpw6dvIHF1ZSBpbmF0aXZhIHRvZG9zIG9zIHVzdcOhcmlvc1xuICBAVXNlR3VhcmRzKEp3dEF1dGhHdWFyZClcbiAgQERlbGV0ZSgnaW5hY3RpdmUnKVxuICBhc3luYyBpbmFjdGl2ZVVzZXJCdWxrKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJTZXJ2aWNlLmluYWN0aXZlVXNlckJ1bGsoKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgZm9yd2FyZFJlZiwgR2xvYmFsLCBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJSZXBvc2l0b3J5IH0gZnJvbSAnLi9yZXBvc2l0b3JpZXMvdXNlci5yZXBvc2l0b3J5JztcbmltcG9ydCB7IFVzZXJDb250cm9sbGVyIH0gZnJvbSAnLi91c2VyLmNvbnRyb2xsZXInO1xuaW1wb3J0IHsgVXNlclNlcnZpY2UgfSBmcm9tICcuL3VzZXIuc2VydmljZSc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoTW9kdWxlIH0gZnJvbSAnLi9lbGFzdGljLXNlYXJjaC9lbGFzdGljLXNlYXJjaC5tb2R1bGUnO1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnO1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJ2FwcHMvYXV0aC9zcmMvYXV0aC5tb2R1bGUnO1xuXG5AR2xvYmFsKClcbkBNb2R1bGUoe1xuICBpbXBvcnRzOiBbXG4gICAgQ29uZmlnTW9kdWxlLmZvclJvb3QoeyBpc0dsb2JhbDogdHJ1ZSB9KSxcbiAgICBUeXBlT3JtTW9kdWxlLmZvclJvb3Qoe1xuICAgICAgdHlwZTogJ215c3FsJyxcbiAgICAgIGhvc3Q6ICdteXNxbF91c2VyJyxcbiAgICAgIGRhdGFiYXNlOiAndXNlcnMnLFxuICAgICAgcG9ydDogMzMwNixcbiAgICAgIHVzZXJuYW1lOiAncm9vdCcsXG4gICAgICBwYXNzd29yZDogJ3Jvb3QnLFxuICAgICAgZW50aXRpZXM6IFtVc2VyXSxcbiAgICAgIHN5bmNocm9uaXplOiBmYWxzZSxcbiAgICAgIGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG4gICAgICBkcm9wU2NoZW1hOiBmYWxzZSxcbiAgICAgIG1pZ3JhdGlvbnNSdW46IGZhbHNlLFxuICAgICAgbG9nZ2luZzogWyd3YXJuJywgJ2Vycm9yJ10sXG4gICAgICBjbGk6IHtcbiAgICAgICAgbWlncmF0aW9uc0RpcjogJ2FwcHMvdXNlci9zcmMvbWlncmF0aW9ucycsXG4gICAgICB9LFxuICAgIH0pLFxuICAgIFR5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbVXNlclJlcG9zaXRvcnldKSxcbiAgICBFbGFzdGljU2VhcmNoTW9kdWxlLFxuICAgIGZvcndhcmRSZWYoKCkgPT4gQXV0aE1vZHVsZSksXG4gIF0sXG4gIHByb3ZpZGVyczogW1VzZXJTZXJ2aWNlXSxcbiAgY29udHJvbGxlcnM6IFtVc2VyQ29udHJvbGxlcl0sXG4gIGV4cG9ydHM6IFtVc2VyU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIFVzZXJNb2R1bGUge31cbiIsImltcG9ydCB7XG4gIEZvcmJpZGRlbkV4Y2VwdGlvbixcbiAgSW5qZWN0YWJsZSxcbiAgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbixcbiAgTm90Rm91bmRFeGNlcHRpb24sXG59IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IENyZWF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by9jcmVhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBSZWNvdmVyUGFzc3dvcmREdG8gfSBmcm9tICcuL2R0by9yZWNvdmVyUGFzc3dvcmQuZHRvJztcbmltcG9ydCB7IFVwZGF0ZVVzZXJEdG8gfSBmcm9tICcuL2R0by91cGRhdGVVc2VyLmR0byc7XG5pbXBvcnQgeyBVc2VyQ2hhbmdlUmVzdWx0IH0gZnJvbSAnLi9kdG8vdXNlckNoYW5nZVJlc3VsdC5kdG8nO1xuaW1wb3J0IHsgVXNlclJlc3BvbnNlRHRvIH0gZnJvbSAnLi9kdG8vdXNlclJlc3BvbnNlLmR0byc7XG5pbXBvcnQgeyBFbGFzdGljU2VhcmNoU2VydmljZSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvZWxhc3RpYy1zZWFyY2guc2VydmljZSc7XG5pbXBvcnQgeyBVc2VyU2VhcmNoQm9keSB9IGZyb20gJy4vZWxhc3RpYy1zZWFyY2gvaW50ZXJmYWNlcy91c2VyU2VhcmNoQm9keS50eXBlJztcbmltcG9ydCB7IFVzZXIgfSBmcm9tICcuL2VudGl0aWVzL3VzZXIuZW50aXR5JztcbmltcG9ydCB7IFVzZXJTdGF0dXMgfSBmcm9tICcuL2VudW1zL3VzZXItc3RhdHVzLmVudW0nO1xuaW1wb3J0IHsgVXNlclJlcG9zaXRvcnkgfSBmcm9tICcuL3JlcG9zaXRvcmllcy91c2VyLnJlcG9zaXRvcnknO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVXNlclNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcihcbiAgICBwcml2YXRlIHVzZXJSZXBvc2l0b3J5OiBVc2VyUmVwb3NpdG9yeSxcbiAgICBwcml2YXRlIGVsYXN0aWNTZWFyY2hTZXJ2aWNlOiBFbGFzdGljU2VhcmNoU2VydmljZSxcbiAgKSB7fVxuXG4gIGFzeW5jIGdldFVzZXJzKFxuICAgIGZpcnN0ID0gMCxcbiAgICBzaXplID0gMCxcbiAgICB1c2VyU2VhcmNoQm9keTogVXNlclNlYXJjaEJvZHkgPSBudWxsLFxuICApOiBQcm9taXNlPFVzZXJSZXNwb25zZUR0bz4ge1xuICAgIGlmICh1c2VyU2VhcmNoQm9keSkge1xuICAgICAgY29uc3QgeyBhZ2VTY2FsZSwgY3JlYXRlZEF0LCB1cGRhdGVkQXQgfSA9IHVzZXJTZWFyY2hCb2R5O1xuXG4gICAgICBjb25zdCB1c2VycyA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZEJ5RmlsdGVycyhcbiAgICAgICAgdXNlclNlYXJjaEJvZHksXG4gICAgICAgIGZpcnN0LFxuICAgICAgICBzaXplLFxuICAgICAgKTtcblxuICAgICAgY29uc3QgY291bnQgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmNvdW50QnlGaWx0ZXJzKHVzZXJTZWFyY2hCb2R5KTtcblxuICAgICAgY29uc3QgdXNlclJlc3BvbnNlRHRvID0gbmV3IFVzZXJSZXNwb25zZUR0byh1c2VycywgY291bnQpO1xuXG4gICAgICByZXR1cm4gdXNlclJlc3BvbnNlRHRvO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXRvcm5hIHRvZG9zIG9zIHVzdcOhcmlvcyBubyBlbGFzdGljIHNlYXJjaCBjb20gbyBzdGF0dXMgYXRpdm9cbiAgICAgIC8vIGNvbnN0IHVzZXJzID0gYXdhaXQgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS5zZWFyY2goXG4gICAgICAvLyAgIGZpcnN0LFxuICAgICAgLy8gICBzaXplLFxuICAgICAgLy8gICBVc2VyU3RhdHVzLkFjdGl2ZSxcbiAgICAgIC8vICAgWydzdGF0dXMnXSxcbiAgICAgIC8vICk7XG5cbiAgICAgIC8vIGNvbnN0IHsgY291bnQgfSA9IGF3YWl0IHRoaXMuZWxhc3RpY1NlYXJjaFNlcnZpY2UuY291bnQoXG4gICAgICAvLyAgIFVzZXJTdGF0dXMuQWN0aXZlLFxuICAgICAgLy8gICBbJ3N0YXR1cyddLFxuICAgICAgLy8gKTtcbiAgICAgIC8vIGNvbnN0IHVzZXJSZXNwb25zZUR0byA9IG5ldyBVc2VyUmVzcG9uc2VEdG8odXNlcnMsIGNvdW50KTtcbiAgICAgIC8vIHJldHVybiB1c2VyUmVzcG9uc2VEdG87XG5cbiAgICAgIC8vIFJldG9ybmEgdG9kb3Mgb3MgdXN1w6FyaW9zIGNvbSBvIHN0YXR1cyBhdGl2bywgZGUgZm9ybWEgcGFnaW5hZGFcbiAgICAgIGNvbnN0IHVzZXJzID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5maW5kQnlGaWx0ZXJzKFxuICAgICAgICB1c2VyU2VhcmNoQm9keSxcbiAgICAgICAgZmlyc3QsXG4gICAgICAgIHNpemUsXG4gICAgICApO1xuXG4gICAgICBjb25zdCBjb3VudCA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuY291bnRCeUZpbHRlcnModXNlclNlYXJjaEJvZHkpO1xuXG4gICAgICBjb25zdCB1c2VyUmVzcG9uc2VEdG8gPSBuZXcgVXNlclJlc3BvbnNlRHRvKHVzZXJzLCBjb3VudCk7XG5cbiAgICAgIHJldHVybiB1c2VyUmVzcG9uc2VEdG87XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgZ2V0VXNlckJ5SWQoaWQ6IHN0cmluZyk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoaWQpO1xuXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICB0aHJvdyBuZXcgTm90Rm91bmRFeGNlcHRpb24oJ07Do28gZXhpc3RlIHVtIHVzdcOhcmlvIGNvbSBvIGlkIHBhc3NhZG8nKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdXNlcjtcbiAgfVxuXG4gIGFzeW5jIGNyZWF0ZVVzZXIoY3JlYXRlVXNlckR0bzogQ3JlYXRlVXNlckR0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgY3BmLCBlbWFpbCwgbG9naW4gfSA9IGNyZWF0ZVVzZXJEdG87XG5cbiAgICBjb25zdCB1c2VyQWxyZWFkeUV4aXN0ID0gYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51c2VyQWxyZWFkeUV4aXN0KFxuICAgICAgY3BmLFxuICAgICAgZW1haWwsXG4gICAgICBsb2dpbixcbiAgICApO1xuXG4gICAgaWYgKHVzZXJBbHJlYWR5RXhpc3QgJiYgdXNlckFscmVhZHlFeGlzdC5sZW5ndGgpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKFxuICAgICAgICBgSsOhIGV4aXN0ZSB1bSB1c3XDoXJpbyBjYWRhc3RyYWRvIGNvbSBvIGNwZiwgZW1haWwgb3UgbG9naW4gcGFzc2Fkb3NgLFxuICAgICAgKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5jcmVhdGVBbmRTYXZlKGNyZWF0ZVVzZXJEdG8pO1xuXG4gICAgICBjb25zdCBjcmVhdGVkVXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICAgIHdoZXJlOiB7IGxvZ2luIH0sXG4gICAgICB9KTtcblxuICAgICAgLy8gYXdhaXQgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS5pbmRleChjcmVhdGVkVXNlcik7XG5cbiAgICAgIHJldHVybiBjcmVhdGVkVXNlcjtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgdXBkYXRlVXNlcihpZDogc3RyaW5nLCB1cGRhdGVVc2VyRHRvOiBVcGRhdGVVc2VyRHRvKTogUHJvbWlzZTxVc2VyPiB7XG4gICAgY29uc3QgeyBjcGYsIGVtYWlsLCBsb2dpbiB9ID0gdXBkYXRlVXNlckR0bztcblxuICAgIGNvbnN0IHVzZXJBbHJlYWR5RXhpc3QgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LnVzZXJBbHJlYWR5RXhpc3QoXG4gICAgICBjcGYsXG4gICAgICBlbWFpbCxcbiAgICAgIGxvZ2luLFxuICAgICk7XG5cbiAgICBpZiAodXNlckFscmVhZHlFeGlzdCAmJiB1c2VyQWxyZWFkeUV4aXN0Lmxlbmd0aCkge1xuICAgICAgY29uc3QgcmVhbGx5QW5vdGhlclVzZXIgPSB1c2VyQWxyZWFkeUV4aXN0LmZpbmQoKHVzZXIpID0+IHVzZXIuaWQgIT09IGlkKTtcblxuICAgICAgaWYgKHJlYWxseUFub3RoZXJVc2VyKSB7XG4gICAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKFxuICAgICAgICAgIGBKw6EgZXhpc3RlIHVtIHVzdcOhcmlvIGNhZGFzdHJhZG8gY29tIG8gY3BmLCBlbWFpbCBvdSBsb2dpbiBwYXNzYWRvc2AsXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZShpZCk7XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS51cGRhdGVBbmRTYXZlKHVzZXIsIHVwZGF0ZVVzZXJEdG8pO1xuXG4gICAgICBjb25zdCB1cGRhdGVkVXNlciA9IGF3YWl0IHRoaXMudXNlclJlcG9zaXRvcnkuZmluZE9uZSh7XG4gICAgICAgIHdoZXJlOiB7IGxvZ2luIH0sXG4gICAgICB9KTtcblxuICAgICAgLy8gYXdhaXQgdGhpcy5lbGFzdGljU2VhcmNoU2VydmljZS51cGRhdGUodXBkYXRlZFVzZXIpO1xuXG4gICAgICByZXR1cm4gdXBkYXRlZFVzZXI7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHJlY292ZXJQYXNzd29yZChyZWNvdmVyUGFzc3dvcmREdG86IFJlY292ZXJQYXNzd29yZER0byk6IFByb21pc2U8VXNlcj4ge1xuICAgIGNvbnN0IHsgY3BmLCBlbWFpbCwgbmFtZSwgbmV3UGFzc3dvcmQgfSA9IHJlY292ZXJQYXNzd29yZER0bztcblxuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgd2hlcmU6IHtcbiAgICAgICAgY3BmLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsICE9PSBlbWFpbCB8fCB1c2VyLm5hbWUgIT09IG5hbWUpIHtcbiAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FeGNlcHRpb24oJ0FzIGluZm9ybWHDp8O1ZXMgcGFzc2FkYXMgZXN0w6NvIGluY29ycmV0YXMnKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy51c2VyUmVwb3NpdG9yeS5jaGFuZ2VQYXNzd29yZEFuZFNhdmUodXNlciwgbmV3UGFzc3dvcmQpO1xuXG4gICAgICByZXR1cm4gdXNlcjtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93IG5ldyBJbnRlcm5hbFNlcnZlckVycm9yRXhjZXB0aW9uKGVyci5zcWxNZXNzYWdlIHx8IGVycik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgZmluZEJ5TG9naW4obG9naW46IHN0cmluZyk6IFByb21pc2U8VXNlcj4ge1xuICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoe1xuICAgICAgd2hlcmU6IHtcbiAgICAgICAgbG9naW4sXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgY2hhbmdlVXNlclN0YXR1cyhcbiAgICBpZDogc3RyaW5nLFxuICAgIHVzZXJTdGF0dXM6IFVzZXJTdGF0dXMsXG4gICk6IFByb21pc2U8VXNlckNoYW5nZVJlc3VsdD4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmZpbmRPbmUoaWQpO1xuXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICB0aHJvdyBuZXcgTm90Rm91bmRFeGNlcHRpb24oJ1VzdcOhcmlvIG7Do28gZXhpc3RlJyk7XG4gICAgfVxuXG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHVwZGF0ZVVzZXJEdG8gPSBuZXcgVXBkYXRlVXNlckR0bygpO1xuICAgICAgdXBkYXRlVXNlckR0by5zdGF0dXMgPSB1c2VyU3RhdHVzO1xuXG4gICAgICBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LnVwZGF0ZUFuZFNhdmUodXNlciwgdXBkYXRlVXNlckR0byk7XG5cbiAgICAgIGNvbnN0IHVzZXJDaGFuZ2VSZXN1bHQ6IFVzZXJDaGFuZ2VSZXN1bHQgPSB7XG4gICAgICAgIGFmZmVjdGVkOiAxLFxuICAgICAgfTtcblxuICAgICAgcmV0dXJuIHVzZXJDaGFuZ2VSZXN1bHQ7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGluYWN0aXZlVXNlckJ1bGsoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdHJ5IHtcbiAgICAgIHJldHVybiBhd2FpdCB0aGlzLnVzZXJSZXBvc2l0b3J5LmluYWN0aXZlQWxsVXNlcnMoKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUubG9nKGVycik7XG4gICAgICB0aHJvdyBuZXcgSW50ZXJuYWxTZXJ2ZXJFcnJvckV4Y2VwdGlvbihlcnIuc3FsTWVzc2FnZSB8fCBlcnIpO1xuICAgIH1cbiAgfVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvZWxhc3RpY3NlYXJjaFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2p3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Bhc3Nwb3J0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImRhdGUtZm5zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInBhc3Nwb3J0LWp3dFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJ0eXBlb3JtXCIpOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0uY2FsbChtb2R1bGUuZXhwb3J0cywgbW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCJpbXBvcnQgeyBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IE5lc3RGYWN0b3J5IH0gZnJvbSAnQG5lc3Rqcy9jb3JlJztcbmltcG9ydCB7IFVzZXJNb2R1bGUgfSBmcm9tICcuL3VzZXIubW9kdWxlJztcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuICBjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoVXNlck1vZHVsZSk7XG4gIGFwcC51c2VHbG9iYWxQaXBlcyhuZXcgVmFsaWRhdGlvblBpcGUoKSk7XG4gIGFwcC5lbmFibGVDb3JzKHsgb3JpZ2luOiBbJ2h0dHA6Ly9sb2NhbGhvc3Q6NDIwMCddIH0pO1xuICBhd2FpdCBhcHAubGlzdGVuKDMwMDApO1xufVxuYm9vdHN0cmFwKCk7XG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=