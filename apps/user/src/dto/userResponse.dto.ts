import { UserSearchBody } from '../elastic-search/interfaces/userSearchBody.type';
import { User } from '../entities/user.entity';

export class UserResponseDto {
  data: User[] | UserSearchBody[];
  count: number;

  public constructor(data: User[] | UserSearchBody[], count: number) {
    this.data = data;
    this.count = count;
  }
}
