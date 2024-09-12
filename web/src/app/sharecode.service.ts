import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class SharecodeService {
  constructor() {}

  public getShareCode(): string {
    return 'BluePenguinBouncer';
  }
}
