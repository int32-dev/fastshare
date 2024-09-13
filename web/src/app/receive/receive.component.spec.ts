import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ReceiveComponent } from './receive.component';

describe('ReceiveComponent', () => {
  let component: ReceiveComponent;
  let fixture: ComponentFixture<ReceiveComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ReceiveComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ReceiveComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
