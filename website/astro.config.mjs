// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://authkestra.com',

	integrations: [
		starlight({
			title: 'Authkestra',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/marcjazz/authkestra' }],
			customCss: [
				'./src/styles/custom.css',
			],
			sidebar: [
				{
					label: 'Welcome',
					items: [
						{ label: 'Why Authkestra?', slug: 'concepts/architecture' },
						{ label: 'Comparison', slug: 'concepts/comparison' },
					],
				},
				{
					label: 'Getting Started',
					items: [
						{ label: 'Quickstart', slug: 'guides/quickstart' },
						{ label: 'Framework Integration', slug: 'guides/framework-integration' },
						{ label: 'Wired Endpoints', slug: 'guides/wired-endpoints' },
					],
				},
				{
					label: 'Authentication Flows',
					items: [
						{ label: 'Stateless OAuth2', slug: 'providers/oauth2' },
						{ label: 'OIDC Provider (Client)', slug: 'providers/oidc' },
						{ label: 'Client Credentials', slug: 'providers/client-credentials' },
						{ label: 'Device Flow', slug: 'providers/device-flow' },
						{ label: 'Passkeys (WebAuthn)', slug: 'providers/passkeys' },
						{ label: 'TOTP (Authenticator Apps)', slug: 'providers/totp' },
						{ label: 'Bot Protection (CAPTCHA)', slug: 'providers/bot-protection' },
						{ label: 'Device Signatures', slug: 'providers/device-signatures' },
					],
				},
				{
					label: 'Building Servers',
					items: [
						{ label: 'Resource Server (API)', slug: 'advanced/resource-server' },
						{ label: 'OpenID Provider (OP)', slug: 'advanced/op-server' },
						{ label: 'Device Attestation', slug: 'guides/device-attestation' },
						{ label: 'Continuous Access Evaluation (CAEP/SSF)', slug: 'advanced/continuous-access-evaluation' },
					],
				},
				{
					label: 'Data & Storage',
					items: [
						{ label: 'Storage Overview', slug: 'storage/overview' },
						{ label: 'KV Stores', slug: 'storage/kv-store' },
						{ label: 'OP SQL Store', slug: 'storage/sql-store' },
						{ label: 'Implementing Custom Stores', slug: 'storage/implementing-stores' },
					],
				},
				{
					label: 'Core Concepts',
					items: [
						{ label: 'Typestate Builder Pattern', slug: 'concepts/typestate-builder' },
						{ label: 'Instrumentation & Tracing', slug: 'advanced/instrumentation' },
					],
				},
			],
		}),
	],
});
