import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginUserDto } from 'apps/user/src/dto/loginUser.dto';
import { User } from 'apps/user/src/entities/user.entity';
import { UserStatus } from 'apps/user/src/enums/user-status.enum';
import { UserService } from 'apps/user/src/user.service';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string }> {
    const user = await this.validateUser(loginUserDto);

    const payload = {
      userId: user.id,
    };

    return {
      accessToken: this.jwtService.sign(payload),
    };
  }

  async validateUser(loginUserDto: LoginUserDto): Promise<User> {
    const { login, password } = loginUserDto;

    const user = await this.userService.findByLogin(login);

    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    if (user.status !== UserStatus.Active) {
      throw new UnauthorizedException(
        `Esse usuário está com o status ${user.status.valueOf()}`,
      );
    }

    const validatePassword = await user.validatePassword(password);

    if (!validatePassword) {
      throw new UnauthorizedException('Login ou senha incorretos');
    }

    return user;
  }
}
