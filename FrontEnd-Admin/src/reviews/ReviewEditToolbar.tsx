import * as React from 'react';
import {Fragment} from 'react';
import Toolbar from '@mui/material/Toolbar';

import {
    SaveButton,
    DeleteButton,
    ToolbarProps,
    useRecordContext,
    useNotify,
    useRedirect,
} from 'react-admin';
import AcceptButton from './AcceptButton';
import RejectButton from './RejectButton';
import {Review} from '../types';

const ReviewEditToolbar = (props: ToolbarProps) => {
    const {resource} = props;
    const redirect = useRedirect();
    const notify = useNotify();

    const record = useRecordContext<Review>(props);

    if (!record) return null;
    return (
        <Toolbar
            sx={{
                display: 'flex',
                justifyContent: 'space-between',
                minHeight: {sm: 0},
            }}
        >
            {record.type === 1 ? (
                <Fragment>
                    <AcceptButton/>
                    <RejectButton/>
                </Fragment>
            ) : (
                <Fragment>
                    <SaveButton
                        label={'Lưu'}
                        mutationOptions={{
                            onSuccess: () => {
                                notify('ra.notification.updated', {
                                    type: 'info',
                                    messageArgs: {smart_count: 1},
                                    undoable: true,
                                });
                                redirect('list', 'review');
                            },
                        }}
                        type="button"
                    />
                    <DeleteButton record={record} resource={resource} label={'Xoá đánh giá'}/>
                </Fragment>
            )}
        </Toolbar>
    );
};

export default ReviewEditToolbar;
