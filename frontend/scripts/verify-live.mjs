import { chromium } from '@playwright/test';
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'msedge', headless: true });
const page = await browser.newPage();
const errors = [];
page.on('pageerror', (error) => errors.push(error.message));
try {
  await page.addInitScript(() => localStorage.setItem('blindshield_connection_mode', 'simulated'));
  await page.goto('http://127.0.0.1:5173/', { waitUntil: 'domcontentloaded' });
  await page.getByTestId('live-backend-console').waitFor();
  await page.getByText('NIL means the running backend has not supplied this value.', { exact: false }).waitFor();
  if (await page.getByText('SIMULATED DATA', {exact:true}).count()) throw new Error('Simulation is selectable.');
  await page.waitForFunction(() => document.querySelector('textarea[aria-label="Backend create request JSON"]')?.value.length > 10);
  await page.getByRole('button', {name:'Create using operator certificate'}).click();
  await page.getByText('CREATED', {exact:true}).waitFor();
  await page.getByRole('button', {name:'seal',exact:true}).click();
  await page.getByText('SEALED', {exact:true}).waitFor();
  await page.getByRole('button', {name:'Red Team',exact:true}).click();
  if (await page.getByText('SEALED',{exact:true}).count()) throw new Error('Previous role status leaked.');
  await page.getByRole('button', {name:'Refresh status'}).click();
  await page.getByText('SEALED',{exact:true}).waitFor();
  await page.getByRole('button', {name:'Blue Team',exact:true}).click();
  await page.getByRole('button', {name:'Refresh status'}).click();
  await page.getByText('EMBARGOED — the backend withheld this role’s status projection.').waitFor();
  if (errors.length) throw new Error(errors.join(' | '));
  console.log(JSON.stringify({result:'PASS',checks:['live default despite stored simulation','NIL availability','public backend profile load','operator create/seal','role status cleared','red status','blue embargo'],model_calls:0}));
} finally { await browser.close(); }
