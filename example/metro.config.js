const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');
const path = require('path');
const escape = require('escape-string-regexp');
const exclusionList = require('metro-config/src/defaults/exclusionList');
const pak = require('../package.json');

const root = path.resolve(__dirname, '..');
const modules = Object.keys({ ...pak.peerDependencies });

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root],

  // We need to make sure that only one version is loaded for peerDependencies
  // So we block them at the root, and alias them to the versions in example's node_modules
  resolver: {
    blacklistRE: exclusionList(
      modules.map(
        (m) =>
          new RegExp(`^${escape(path.join(root, 'node_modules', m))}\\/.*$`)
      )
    ),

    extraNodeModules: modules.reduce(
      (acc, name) => {
        acc[name] = path.join(__dirname, 'node_modules', name);
        return acc;
      },
      {
        stream: path.resolve(__dirname, './node_modules/stream-browserify'),
        events: path.resolve(__dirname, './node_modules/events'),
        process: path.resolve(__dirname, './node_modules/process'),
        buffer: path.resolve(
          __dirname,
          './node_modules/@craftzdog/react-native-buffer'
        ),
        tape: path.resolve(__dirname, './tape-to-mocha'),
      }
    ),
  },

  transformer: {
    getTransformOptions: async () => ({
      transform: {
        experimentalImportSupport: false,
        inlineRequires: true,
      },
    }),
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
