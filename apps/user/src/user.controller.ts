import {
  Body,
  Controller,
  Delete,
  Get,
  OnModuleInit,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'apps/auth/src/jwt/jwt-auth.guard';
import { DeleteResult } from 'typeorm';
import { CreateUserDto } from './dto/createUser.dto';
import { RecoverPasswordDto } from './dto/recoverPassword.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { UserSearchBody } from './elastic-search/interfaces/userSearchBody.type';
import { User } from './entities/user.entity';
import { UserService } from './user.service';

@Controller('api/v1/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // Serviço que retorna todos os usuários
  @UseGuards(JwtAuthGuard)
  @Get()
  async getUsers(): Promise<User[] | UserSearchBody[]> {
    return await this.userService.getUsers();
  }

  // Serviço que retorna os usuários de forma paginada, possibilitando inserir filtros na busca
  @UseGuards(JwtAuthGuard)
  @Post('byFilters')
  async getUsersByFilters(
    @Body() userSearchBody: UserSearchBody,
  ): Promise<User[] | UserSearchBody[]> {
    return await this.userService.getUsers(userSearchBody);
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

  // Serviço que exclui um usuário
  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  async deleteUser(@Param('id') id: string): Promise<DeleteResult> {
    return await this.userService.deleteUser(id);
  }
}
