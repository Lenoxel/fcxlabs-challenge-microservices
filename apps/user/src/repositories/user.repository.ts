import { EntityRepository, Repository } from 'typeorm';
import { CreateUserDto } from '../dto/createUser.dto';
import { UpdateUserDto } from '../dto/updateUser.dto';
import { UserSearchBody } from '../elastic-search/interfaces/userSearchBody.type';
import { User } from '../entities/user.entity';
import { UserStatus } from '../enums/user-status.enum';
import { AgeScaleClass } from '../models/age-scale.model';
import { startOfDay, endOfDay } from 'date-fns';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  // Busca os usuários, de forma paginada, através dos filtros passados
  async findByFilters(
    userSearchBody: UserSearchBody,
    first = 0,
    size = 0,
  ): Promise<User[]> {
    if (userSearchBody) {
      const { name, login, cpf, status, ageScale, createdAt, updatedAt } =
        userSearchBody;

      const queryBuilder = this.createQueryBuilder('user');

      let firstWhere = true;

      if (name) {
        if (firstWhere) {
          queryBuilder.where('user.name like :name', { name: `%${name}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.name like :name', { name: `%${name}%` });
        }
      }

      if (login) {
        if (firstWhere) {
          queryBuilder.where('user.login like :login', { login: `%${login}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.login like :login', {
            login: `%${login}%`,
          });
        }
      }

      if (cpf) {
        if (firstWhere) {
          queryBuilder.where('user.cpf like :cpf', { cpf: `%${cpf}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.cpf like :cpf', { cpf: `%${cpf}%` });
        }
      }

      if (status) {
        if (firstWhere) {
          queryBuilder.where('user.status = :status', { status });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.status = :status', { status });
        }
      }

      if (ageScale) {
        const ageScaleClass = new AgeScaleClass(ageScale);
        if (firstWhere) {
          if (ageScaleClass.getStart()) {
            queryBuilder.where('user.birthDate BETWEEN :start AND :end', {
              start: ageScaleClass.getStart(),
              end: ageScaleClass.getEnd(),
            });
          } else {
            queryBuilder.where('user.birthDate < :end', {
              end: ageScaleClass.getEnd(),
            });
          }
          firstWhere = false;
        } else {
          if (ageScaleClass.getStart()) {
            queryBuilder.andWhere('user.birthDate BETWEEN :start AND :end', {
              start: ageScaleClass.getStart(),
              end: ageScaleClass.getEnd(),
            });
          } else {
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
              createdAtStartDate: startOfDay(createdAt.start).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.createdAt >= :createdAtStartDate', {
              createdAtStartDate: startOfDay(createdAt.start).toISOString(),
            });
          }
        }

        if (createdAt.end) {
          if (firstWhere) {
            queryBuilder.where('user.createdAt <= :createdAtEndDate', {
              createdAtEndDate: endOfDay(createdAt.end).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.createdAt <= :createdAtEndDate', {
              createdAtEndDate: endOfDay(createdAt.end).toISOString(),
            });
          }
        }
      }

      if (updatedAt) {
        if (updatedAt.start) {
          if (firstWhere) {
            queryBuilder.where('user.updatedAt >= :updatedAtStartDate', {
              updatedAtStartDate: startOfDay(updatedAt.start).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.updatedAt >= :updatedAtStartDate', {
              updatedAtStartDate: startOfDay(updatedAt.start).toISOString(),
            });
          }
        }

        if (updatedAt.end) {
          if (firstWhere) {
            queryBuilder.where('user.updatedAt <= :updatedAtEndDate', {
              updatedAtEndDate: endOfDay(updatedAt.end).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.updatedAt <= :updatedAtEndDate', {
              updatedAtEndDate: endOfDay(updatedAt.end).toISOString(),
            });
          }
        }
      }

      if (size > 0) {
        queryBuilder.skip(first).take(size);
      }

      return await queryBuilder.getMany();
    } else {
      const queryBuilder = this.createQueryBuilder('user').where(
        'user.status != :status',
        {
          status: UserStatus.Inactive,
        },
      );

      if (size > 0) {
        queryBuilder.skip(first).take(size);
      }

      return await queryBuilder.getMany();
    }
  }

  // Conta o total de usuários através dos filtros passados
  async countByFilters(userSearchBody: UserSearchBody): Promise<number> {
    if (userSearchBody) {
      const { name, login, cpf, status, ageScale, createdAt, updatedAt } =
        userSearchBody;

      const queryBuilder = this.createQueryBuilder('user');

      let firstWhere = true;

      if (name) {
        if (firstWhere) {
          queryBuilder.where('user.name like :name', { name: `%${name}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.name like :name', { name: `%${name}%` });
        }
      }

      if (login) {
        if (firstWhere) {
          queryBuilder.where('user.login like :login', { login: `%${login}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.login like :login', {
            login: `%${login}%`,
          });
        }
      }

      if (cpf) {
        if (firstWhere) {
          queryBuilder.where('user.cpf like :cpf', { cpf: `%${cpf}%` });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.cpf like :cpf', { cpf: `%${cpf}%` });
        }
      }

      if (status) {
        if (firstWhere) {
          queryBuilder.where('user.status = :status', { status });
          firstWhere = false;
        } else {
          queryBuilder.andWhere('user.status = :status', { status });
        }
      }

      if (ageScale) {
        const ageScaleClass = new AgeScaleClass(ageScale);
        if (firstWhere) {
          if (ageScaleClass.getStart()) {
            queryBuilder.where('user.birthDate BETWEEN :start AND :end', {
              start: ageScaleClass.getStart(),
              end: ageScaleClass.getEnd(),
            });
          } else {
            queryBuilder.where('user.birthDate < :end', {
              end: ageScaleClass.getEnd(),
            });
          }
          firstWhere = false;
        } else {
          if (ageScaleClass.getStart()) {
            queryBuilder.andWhere('user.birthDate BETWEEN :start AND :end', {
              start: ageScaleClass.getStart(),
              end: ageScaleClass.getEnd(),
            });
          } else {
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
              createdAtStartDate: startOfDay(createdAt.start).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.createdAt >= :createdAtStartDate', {
              createdAtStartDate: startOfDay(createdAt.start).toISOString(),
            });
          }
        }

        if (createdAt.end) {
          if (firstWhere) {
            queryBuilder.where('user.createdAt <= :createdAtEndDate', {
              createdAtEndDate: endOfDay(createdAt.end).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.createdAt <= :createdAtEndDate', {
              createdAtEndDate: endOfDay(createdAt.end).toISOString(),
            });
          }
        }
      }

      if (updatedAt) {
        if (updatedAt.start) {
          if (firstWhere) {
            queryBuilder.where('user.updatedAt >= :updatedAtStartDate', {
              updatedAtStartDate: startOfDay(updatedAt.start).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.updatedAt >= :updatedAtStartDate', {
              updatedAtStartDate: startOfDay(updatedAt.start).toISOString(),
            });
          }
        }

        if (updatedAt.end) {
          if (firstWhere) {
            queryBuilder.where('user.updatedAt <= :updatedAtEndDate', {
              updatedAtEndDate: endOfDay(updatedAt.end).toISOString(),
            });
            firstWhere = false;
          } else {
            queryBuilder.andWhere('user.updatedAt <= :updatedAtEndDate', {
              updatedAtEndDate: endOfDay(updatedAt.end).toISOString(),
            });
          }
        }
      }

      return await queryBuilder.getCount();
    } else {
      return this.createQueryBuilder('user')
        .where('user.status != :status', {
          status: UserStatus.Inactive,
        })
        .getCount();
    }
  }

  // Verifica se um usuário já existe na base de dados
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

  // Salva um novo usuário na base de dados
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

  // Atualiza os dados de um usuário já existente na base de dados
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

  // Altera a senha de um usuário (recuperação de senha)
  async changePasswordAndSave(user: User, newPassword: string) {
    user.password = newPassword;
    await this.save(user);
  }

  // Inativa todos os usuários do sistema
  async inactiveAllUsers() {
    await this.createQueryBuilder()
      .update(User)
      .set({ status: UserStatus.Inactive })
      .execute();
  }
}
