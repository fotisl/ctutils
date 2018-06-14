import rollupNodeResolve from 'rollup-plugin-node-resolve';

export default [
  {
    input: 'examples/html/GetRoots/src.js',
    plugins: [
      rollupNodeResolve({ jsnext: true, main: true })
    ],
    output: [
      {
        file: 'examples/html/GetRoots/bundle.js',
        name: 'ctBundle',
        format: 'iife',
      }
    ]
  },
  {
    input: 'examples/html/FetchNewCerts/src.js',
    plugins: [
      rollupNodeResolve({ jsnext: true, main: true })
    ],
    output: [
      {
        file: 'examples/html/FetchNewCerts/bundle.js',
        name: 'ctBundle',
        format: 'iife',
      }
    ]
  }
];
