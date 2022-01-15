import { UserSearchBody } from './userSearchBody.type';

export interface UserSearchResult {
  hits: {
    total: number;
    hits: Array<{
      _source: UserSearchBody;
    }>;
  };
}
