import { TestBed } from '@angular/core/testing';

import { SharecodeService } from './sharecode.service';

describe('SharecodeService', () => {
  let service: SharecodeService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(SharecodeService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
