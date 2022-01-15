import { AgeScale } from '../../enums/age-scale.enum';
import { UserStatus } from '../../enums/user-status.enum';

export interface UserSearchBody {
  id: number;
  name: string;
  login: string;
  cpf: string;
  status: UserStatus;
  ageScale: AgeScale;
  ageRange?: {
    start: number;
    end: number;
  };
  birthDate?: {
    start: Date;
    end: Date;
  };
  createdAt?: {
    start: Date;
    end: Date;
  };
  updatedAt?: {
    start: Date;
    end: Date;
  };
}
