import React, {Fragment, useEffect, useState} from "react";
import Breadcrumb from "../../wrappers/breadcrumb/Breadcrumb";
import PostSidebar from "../../wrappers/blog/PostSidebar";
import Post from "../../wrappers/blog/Post";
import Comment from "../../wrappers/blog/Comment";
import axios from "axios";
import {useLoaderData} from "react-router";

export function loadIdPost({params}: any) {
    return {id: parseInt(params.id)};
}

const PostDetail = () => {
    const received: any = useLoaderData()
    const [post, setPost] = useState(null);
    useEffect(() => {
        const fectch = async () => {
            await axios.get(`http://localhost:8080/api/blog/` + received.id, {
                headers: {
                    Accept: 'application/json',
                    "Content-Type": "application/json"
                }
            }).then(response => {
                console.log("hihi"+response.data)
                setPost(response.data);
            })
        }
        fectch().then();
    }, [received]);
    console.log(post)
    return ( post &&
        <Fragment>
            <Breadcrumb/>
            <div className="blog-area pt-100 pb-100">
                <div className="container">
                    <div className="row flex-row-reverse">
                        <div className="col-lg-9">
                            <div className="blog-details-wrapper ml-20">
                                <Post post={post}/>
                            </div>
                        </div>
                        <div className="col-lg-3">
                            <PostSidebar/>
                        </div>
                    </div>
                </div>
            </div>
        </Fragment>
    );
};

export default PostDetail;
