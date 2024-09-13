import { Routes } from '@angular/router';
import { HomePageComponent } from './home-page/home-page.component';
import { SendComponent } from './send/send.component';
import { ReceiveComponent } from './receive/receive.component';

export const routes: Routes = [
  { path: '', component: HomePageComponent },
  { path: 'send', component: SendComponent },
  { path: 'receive', component: ReceiveComponent },
];
