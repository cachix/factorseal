export interface Field {
  label: string;
  icon: string;
  value: string;
  concealed?: boolean;
  totp?: boolean;
}

export interface Section {
  heading?: string;
  fields: Field[];
}

export interface Item {
  id: string;
  title: string;
  kind: 'Login' | 'Card' | 'Identity' | 'Secure note';
  icon: string;
  subtitle: string;
  favorite?: boolean;
  sections: Section[];
}

export const totpSecret = 'JBSWY3DPEHPK3PXP';
export const modified = 'Modified 23 October 2026';

const login = (id: string, title: string, username: string, password: string, website: string, options: { favorite?: boolean; totp?: boolean } = {}): Item => ({
  id,
  title,
  kind: 'Login',
  icon: 'globe',
  subtitle: username,
  favorite: options.favorite,
  sections: [{
    fields: [
      { label: 'Username', icon: 'user', value: username },
      { label: 'Password', icon: 'fs:key', value: password, concealed: true },
      ...(options.totp ? [{ label: 'One-time password', icon: 'fs:clock', value: '', totp: true }] : []),
      { label: 'Website', icon: 'globe', value: website },
    ],
  }],
});

export const items: Item[] = [
  login('fastmail', 'Fastmail', 'john@example.com', 'vX7#qLm2!pR9sT4w', 'https://app.fastmail.com', { favorite: true }),
  login('github', 'GitHub', 'john.doe', 'Kd8$wq3Lz!mN0rTe', 'https://github.com', { favorite: true, totp: true }),
  {
    id: 'identity',
    title: 'John Doe',
    kind: 'Identity',
    icon: 'circle-user',
    subtitle: 'john.doe',
    sections: [
      {
        heading: 'Identification',
        fields: [
          { label: 'First name', icon: 'user', value: 'John' },
          { label: 'Last name', icon: 'user', value: 'Doe' },
        ],
      },
      {
        heading: 'Internet Details',
        fields: [
          { label: 'Username', icon: 'user', value: 'john.doe' },
          { label: 'Email', icon: 'fs:mail', value: 'john@example.com' },
        ],
      },
    ],
  },
  {
    id: 'visa',
    title: 'Everyday Visa',
    kind: 'Card',
    icon: 'fs:card',
    subtitle: 'Card',
    sections: [{
      fields: [
        { label: 'Cardholder', icon: 'user', value: 'John Doe' },
        { label: 'Type', icon: 'fs:tag', value: 'Visa' },
        { label: 'Card number', icon: 'fs:card', value: '4111111111111111', concealed: true },
        { label: 'Security code', icon: 'fs:lock', value: '123', concealed: true },
        { label: 'Expiry date', icon: 'calendar', value: '08/2029' },
      ],
    }],
  },
  login('figma', 'Figma', 'john@example.com', 'pQ4!nW8@zR2#kL6m', 'https://www.figma.com'),
  login('hetzner', 'Hetzner Cloud', 'john.doe', 'Hz5%tY1&bN7*cV3x', 'https://console.hetzner.cloud'),
  {
    id: 'wifi',
    title: 'Home Wi-Fi',
    kind: 'Secure note',
    icon: 'file',
    subtitle: 'Secure note',
    sections: [{
      fields: [{ label: 'Notes', icon: 'file', value: 'Network: Doe Home\nPassword: correct-horse-battery' }],
    }],
  },
  login('tailscale', 'Tailscale', 'john@example.com', 'Ts9^gH4!jK2@wE7q', 'https://login.tailscale.com'),
];
