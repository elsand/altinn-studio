import React from 'react';
import { makeStyles,
  FormControl,
  Input,
  InputLabel,
  InputAdornment,
  IconButton } from '@material-ui/core';
import {CreateOutlined, DoneOutlined} from '@material-ui/icons';

const useStyles = makeStyles({
  root: {
    margin: 12,
  },
  rootKey: {
    margin: 12,
  },
  inline: {
    display: 'inline-block',
  },
  label: {
    margin: 12,
  }
});

export interface IInputFieldProps {
  value: string;
  label: string;
  fullPath: string;
  onChangeValue: (path: string, value: string) => void;
  onChangeKey: (path: string, oldKey: string, newKey: string) => void;
}

export function InputField(props: IInputFieldProps) {
  const classes = useStyles();
  const [value, setValue] = React.useState<string>(props.value || '');
  const [label, setLabel] = React.useState<string>(props.label || '');
  const [editLabel, setEditLabel] = React.useState<boolean>(false);

  React.useEffect(() => {
    setValue(props.value);
  }, [props.value]);

  const onChangeValue = (e: any) => {
    setValue(e.target.value);
    props.onChangeValue(props.fullPath, e.target.value);
  }

  const onChangeKey = (e: any) => {
    const oldLabel = label;
    setLabel(e.target.value);
    props.onChangeKey(props.fullPath, oldLabel, e.target.value);
  }

  const toggleEditLabel = (e: any) => {
    setEditLabel(!editLabel);
  }

  return (
      <div>
        <FormControl>
          <Input
            id={`input-${props.fullPath}-key`}
            value={label}
            onChange={onChangeKey}
            disabled={!editLabel}
            className={classes.rootKey}
            endAdornment={
              <InputAdornment position='end'>
                <IconButton onClick={toggleEditLabel}>
                  {editLabel ? <DoneOutlined /> : <CreateOutlined />}
                </IconButton>
              </InputAdornment>
            }
          />
        </FormControl>
        <FormControl>
          <Input
            value={value}
            onChange={onChangeValue}
            className={classes.root}
          />
        </FormControl>
      </div>
  )
}