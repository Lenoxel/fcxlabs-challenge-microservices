import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/createUser.dto';
import { RecoverPasswordDto } from './dto/recoverPassword.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { UserChangeResult } from './dto/userChangeResult.dto';
import { UserResponseDto } from './dto/userResponse.dto';
import { ElasticSearchService } from './elastic-search/elastic-search.service';
import { UserSearchBody } from './elastic-search/interfaces/userSearchBody.type';
import { User } from './entities/user.entity';
import { UserStatus } from './enums/user-status.enum';
import { UserRepository } from './repositories/user.repository';

@Injectable()
export class UserService {
  constructor(
    private userRepository: UserRepository,
    private elasticSearchService: ElasticSearchService,
  ) {}

  async getUsers(
    first = 0,
    size = 0,
    userSearchBody: UserSearchBody = null,
  ): Promise<UserResponseDto> {
    if (userSearchBody) {
      const { ageScale, createdAt, updatedAt } = userSearchBody;

      if (ageScale || createdAt || updatedAt || true) {
        const users = await this.userRepository.findByFilters(
          userSearchBody,
          first,
          size,
        );

        const count = await this.userRepository.countByFilters(userSearchBody);

        const userResponseDto = new UserResponseDto(users, count);

        return userResponseDto;
      } else {
        let userSearchBodyList: UserSearchBody[] = [];

        let index = 1;

        for (const [attributeName, attributeValue] of Object.entries(
          userSearchBody,
        )) {
          if (attributeValue) {
            const partialSearch = await this.elasticSearchService.search(
              first,
              size,
              attributeValue,
              [attributeName],
            );
            userSearchBodyList =
              index > 1
                ? partialSearch.filter((item) =>
                    userSearchBodyList.includes(item),
                  )
                : [...partialSearch];
            index += 1;
          }
        }

        const userResponseDto = new UserResponseDto(
          userSearchBodyList,
          userSearchBodyList.length,
        );

        return userResponseDto;
      }
    } else {
      // Retorna todos os usuários no elastic search com o status ativo
      // const users = await this.elasticSearchService.search(
      //   first,
      //   size,
      //   UserStatus.Active,
      //   ['status'],
      // );

      // const { count } = await this.elasticSearchService.count(
      //   UserStatus.Active,
      //   ['status'],
      // );
      // const userResponseDto = new UserResponseDto(users, count);
      // return userResponseDto;

      // Retorna todos os usuários com o status ativo, de forma paginada
      const users = await this.userRepository.findByFilters(
        userSearchBody,
        first,
        size,
      );

      const count = await this.userRepository.countByFilters(userSearchBody);

      const userResponseDto = new UserResponseDto(users, count);

      return userResponseDto;
    }
  }

  async getUserById(id: string): Promise<User> {
    const user = await this.userRepository.findOne(id);

    if (!user) {
      throw new NotFoundException('Não existe um usuário com o id passado');
    }

    return user;
  }

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    const { cpf, email, login } = createUserDto;

    const userAlreadyExist = await this.userRepository.userAlreadyExist(
      cpf,
      email,
      login,
    );

    if (userAlreadyExist && userAlreadyExist.length) {
      throw new InternalServerErrorException(
        `Já existe um usuário cadastrado com o cpf, email ou login passados`,
      );
    }

    try {
      await this.userRepository.createAndSave(createUserDto);

      const createdUser = await this.userRepository.findOne({
        where: { login },
      });

      // await this.elasticSearchService.index(createdUser);

      return createdUser;
    } catch (err) {
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }

  async updateUser(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const { cpf, email, login } = updateUserDto;

    const userAlreadyExist = await this.userRepository.userAlreadyExist(
      cpf,
      email,
      login,
    );

    if (userAlreadyExist && userAlreadyExist.length) {
      const reallyAnotherUser = userAlreadyExist.find((user) => user.id !== id);

      if (reallyAnotherUser) {
        throw new InternalServerErrorException(
          `Já existe um usuário cadastrado com o cpf, email ou login passados`,
        );
      }
    }

    const user = await this.userRepository.findOne(id);

    try {
      await this.userRepository.updateAndSave(user, updateUserDto);

      const updatedUser = await this.userRepository.findOne({
        where: { login },
      });

      // await this.elasticSearchService.update(updatedUser);

      return updatedUser;
    } catch (err) {
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }

  async recoverPassword(recoverPasswordDto: RecoverPasswordDto): Promise<User> {
    const { cpf, email, name, newPassword } = recoverPasswordDto;

    const user = await this.userRepository.findOne({
      where: {
        cpf,
      },
    });

    if (!user || user.email !== email || user.name !== name) {
      throw new ForbiddenException('As informações passadas estão incorretas');
    }

    try {
      await this.userRepository.changePasswordAndSave(user, newPassword);

      return user;
    } catch (err) {
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }

  async findByLogin(login: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {
        login,
      },
    });
  }

  async changeUserStatus(
    id: string,
    userStatus: UserStatus,
  ): Promise<UserChangeResult> {
    const user = await this.userRepository.findOne(id);

    if (!user) {
      throw new NotFoundException('Usuário não existe');
    }

    try {
      const updateUserDto = new UpdateUserDto();
      updateUserDto.status = userStatus;

      await this.userRepository.updateAndSave(user, updateUserDto);

      const userChangeResult: UserChangeResult = {
        affected: 1,
      };

      return userChangeResult;
    } catch (err) {
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }

  async inactiveUserBulk(): Promise<void> {
    try {
      return await this.userRepository.inactiveAllUsers();
    } catch (err) {
      console.log(err);
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }
}
