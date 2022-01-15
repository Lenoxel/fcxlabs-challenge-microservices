import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { DeleteResult } from 'typeorm';
import { CreateUserDto } from './dto/createUser.dto';
import { RecoverPasswordDto } from './dto/recoverPassword.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { ElasticSearchService } from './elastic-search/elastic-search.service';
import { UserSearchBody } from './elastic-search/interfaces/userSearchBody.type';
import { User } from './entities/user.entity';
import { UserRepository } from './repositories/user.repository';

@Injectable()
export class UserService {
  constructor(
    private userRepository: UserRepository,
    private elasticSearchService: ElasticSearchService,
  ) {}

  async getUsers(
    userSearchBody: UserSearchBody = null,
  ): Promise<User[] | UserSearchBody[]> {
    if (userSearchBody) {
      const { birthDate, createdAt, updatedAt } = userSearchBody;

      if (birthDate || createdAt || updatedAt) {
        return this.userRepository.findByFilters(userSearchBody);
      } else {
        let userSearchBodyList: UserSearchBody[] = [];

        let index = 1;

        for (const [attributeName, attributeValue] of Object.entries(
          userSearchBody,
        )) {
          if (attributeValue) {
            const partialSearch = await this.elasticSearchService.search(
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

        return userSearchBodyList;
      }
    } else {
      return this.userRepository.findByFilters(null);
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

      this.elasticSearchService.index(createdUser);

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

  async deleteUser(id: string): Promise<DeleteResult> {
    try {
      const deleteResponse = await this.userRepository.delete(id);

      if (!deleteResponse.affected) {
        throw new NotFoundException('Usuário não encontrado');
      }

      await this.elasticSearchService.remove(id);

      return deleteResponse;
    } catch (err) {
      throw new InternalServerErrorException(err.sqlMessage || err);
    }
  }
}
