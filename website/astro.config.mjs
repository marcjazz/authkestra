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
			sidebar: [
				{
					label: 'Introduction & Concepts',
					items: [
						{ label: 'Architecture', slug: 'concepts/architecture' },
						{ label: 'Typestate Builder Pattern', slug: 'concepts/typestate-builder' },
						{ label: 'Authkestra vs. The World', slug: 'concepts/comparison' },
					],
				},
				{
					label: 'Getting Started',
					items: [
						{ label: 'Quickstart', slug: 'guides/quickstart' },
						{ label: 'Wired Endpoints', slug: 'guides/wired-endpoints' },
						{ label: 'Framework Integration', slug: 'guides/framework-integration' },
					],
				},
				{
					label: 'Identity Providers',
					items: [
						{ label: 'Stateless OAuth2', slug: 'providers/oauth2' },
						{ label: 'OIDC Provider', slug: 'providers/oidc' },
						{ label: 'Client Credentials', slug: 'providers/client-credentials' },
						{ label: 'Device Flow', slug: 'providers/device-flow' },
					],
				},
				{
					label: 'Storage & Data Access',
					items: [
						{ label: 'Overview', slug: 'storage/overview' },
						{ label: 'Implementing Stores', slug: 'storage/implementing-stores' },
					],
				},
				{
					label: 'Advanced & Servers',
					items: [
						{ label: 'Resource Server', slug: 'advanced/resource-server' },
						{ label: 'OpenID Provider (OP) Server', slug: 'advanced/op-server' },
						{ label: 'Instrumentation & Tracing', slug: 'advanced/instrumentation' },
					],
				},
			],
		}),
	],
});
