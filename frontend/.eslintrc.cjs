module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true,
    },
  },
  plugins: ['@typescript-eslint', 'react', 'react-hooks', 'jsx-a11y'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react/recommended',
    'plugin:react-hooks/recommended',
    'plugin:jsx-a11y/recommended',
  ],
  settings: {
    react: {
      version: 'detect',
    },
  },
  rules: {
    // Invariant 4: Untrusted text is inert; dangerouslySetInnerHTML is strictly banned repo-wide
    'react/no-danger': 'error',
    'react/react-in-jsx-scope': 'off',
    'react/prop-types': 'off',
    '@typescript-eslint/no-unused-vars': [
      'error',
      {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      },
    ],
    '@typescript-eslint/no-explicit-any': 'warn',
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    'jsx-a11y/no-noninteractive-tabindex': [
      'error',
      {
        roles: ['tabpanel', 'region'],
      },
    ],
    // React Three Fiber intrinsic attributes
    'react/no-unknown-property': [
      'error',
      {
        ignore: [
          'args',
          'wireframe',
          'transparent',
          'position',
          'rotation',
          'side',
          'attach',
          'visible',
        ],
      },
    ],
  },
  ignorePatterns: [
    'dist',
    'node_modules',
    '*.cjs',
    'vite.config.ts',
    'tailwind.config.js',
    'postcss.config.js',
    'playwright.config.ts',
    'test-results',
  ],
};
