import { EntityRepository, Repository } from 'typeorm';
import { CreateUserDto } from '../dto/createUser.dto';
import { UpdateUserDto } from '../dto/updateUser.dto';
import { UserSearchBody } from '../elastic-search/interfaces/userSearchBody.type';
import { User } from '../entities/user.entity';
import { UserStatus } from '../enums/user-status.enum';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  async findByFilters(userSearchBody: UserSearchBody): Promise<User[]> {
    if (userSearchBody) {
      const {
        name,
        login,
        cpf,
        status,
        ageRange,
        birthDate,
        createdAt,
        updatedAt,
      } = userSearchBody;

      const queryBuilder = this.createQueryBuilder('user');

      let firstWhere = true;

      if (name) {
        if (firstWhere) {
          queryBuilder.where('user.name = :name', { name });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.name = :name', { name });
        }
      }

      if (login) {
        if (firstWhere) {
          queryBuilder.where('user.login = :login', { login });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.login = :login', { login });
        }
      }

      if (cpf) {
        if (firstWhere) {
          queryBuilder.where('user.cpf = :cpf', { cpf });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.cpf = :cpf', { cpf });
        }
      }

      if (status) {
        if (firstWhere) {
          queryBuilder.where('user.status = :status', { status });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.status = :status', { status });
        }
      } else {
        queryBuilder.andWhere('user.status = :status', {
          status: UserStatus.Active,
        });
      }

      return await queryBuilder.getMany();
    } else {
      return this.createQueryBuilder('user')
        .where('user.status = :status', {
          status: UserStatus.Active,
        })
        .getMany();
    }
  }

  async userAlreadyExist(
    cpf: string,
    email: string,
    login: string,
  ): Promise<User[]> {
    return this.createQueryBuilder('user')
      .where('user.cpf = :cpf', { cpf })
      .orWhere('user.email = :email', { email })
      .orWhere('user.login = :login', { login })
      .getMany();
  }

  async createAndSave({
    name,
    login,
    password,
    email,
    phoneNumber,
    cpf,
    birthDate,
    motherName,
    status,
  }: CreateUserDto) {
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

  async updateAndSave(
    user: User,
    {
      name,
      login,
      password,
      email,
      phoneNumber,
      cpf,
      birthDate,
      motherName,
      status,
    }: UpdateUserDto,
  ) {
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

  async changePasswordAndSave(user: User, newPassword: string) {
    user.password = newPassword;
    await this.save(user);
  }
}
