import { AgeScale } from '../../enums/age-scale.enum';
import { UserStatus } from '../../enums/user-status.enum';

export interface UserSearchBody {
  id: string;
  name: string;
  login: string;
  cpf: string;
  status: UserStatus;
  ageScale: AgeScale;
  createdAt?: {
    start: number;
    end: number;
  };
  updatedAt?: {
    start: number;
    end: number;
  };
}
