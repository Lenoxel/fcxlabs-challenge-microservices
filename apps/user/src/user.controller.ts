import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'apps/auth/src/jwt/jwt-auth.guard';
import { DeleteResult } from 'typeorm';
import { CreateUserDto } from './dto/createUser.dto';
import { RecoverPasswordDto } from './dto/recoverPassword.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { UserChangeResult } from './dto/userChangeResult.dto';
import { UserResponseDto } from './dto/userResponse.dto';
import { UserSearchBody } from './elastic-search/interfaces/userSearchBody.type';
import { User } from './entities/user.entity';
import { UserStatus } from './enums/user-status.enum';
import { UserService } from './user.service';

@Controller('api/v1/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // Serviço que retorna todos os usuários
  @UseGuards(JwtAuthGuard)
  @Get()
  async getUsers(): Promise<UserResponseDto> {
    return await this.userService.getUsers();
  }

  // Serviço que retorna os usuários de forma paginada, possibilitando inserir filtros na busca
  @UseGuards(JwtAuthGuard)
  @Post('byFilters')
  async getUsersByFilters(
    @Body() userSearchBody: UserSearchBody,
    @Query('first') first: number,
    @Query('size') size: number,
  ): Promise<UserResponseDto> {
    return await this.userService.getUsers(first, size, userSearchBody);
  }

  // Serviço que retorna um usuário pelo seu id
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  async getUserById(@Param('id') id: string): Promise<User> {
    return await this.userService.getUserById(id);
  }

  // Serviço de criação de um usuário
  @Post('/')
  async createUser(@Body() createUserDto: CreateUserDto): Promise<User> {
    return await this.userService.createUser(createUserDto);
  }

  // Serviço de atualização de um usuário
  @UseGuards(JwtAuthGuard)
  @Put(':id')
  async updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<User> {
    return await this.userService.updateUser(id, updateUserDto);
  }

  // Serviço que permite a um usuário recuperar o seu acesso alterando a senha
  @Put('password/recover')
  async recoverPassword(
    @Body() recoverPasswordDto: RecoverPasswordDto,
  ): Promise<User> {
    return await this.userService.recoverPassword(recoverPasswordDto);
  }

  // Serviço que altera o status de um usuário
  @UseGuards(JwtAuthGuard)
  @Put(':id/status')
  async changeUserStatus(
    @Param('id') id: string,
    @Body() { status }: { status: UserStatus },
  ): Promise<UserChangeResult> {
    return await this.userService.changeUserStatus(id, status);
  }

  // Serviço que inativa todos os usuários
  @UseGuards(JwtAuthGuard)
  @Delete('inactive')
  async inactiveUserBulk(): Promise<void> {
    return await this.userService.inactiveUserBulk();
  }
}
