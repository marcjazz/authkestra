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
					],
				},
				{
					label: 'Building Servers',
					items: [
						{ label: 'Resource Server (API)', slug: 'advanced/resource-server' },
						{ label: 'OpenID Provider (OP)', slug: 'advanced/op-server' },
					],
				},
				{
					label: 'Data & Storage',
					items: [
						{ label: 'Storage Overview', slug: 'storage/overview' },
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
