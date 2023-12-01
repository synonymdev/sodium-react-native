import React, { type ReactElement } from 'react';
import { Text as RNText, StyleSheet, type TextProps } from 'react-native';

type Props = TextProps;

const Text = ({ style, ...props }: Props): ReactElement => (
  <RNText style={[styles.root, style]} {...props}>
    {props.children}
  </RNText>
);

const styles = StyleSheet.create({
  root: {
    color: 'black',
  },
});

export default Text;
